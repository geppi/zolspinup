#!/bin/python3
# -*- coding: utf-8 -*-
# Copyright (c) 2023, 2024, 2025 Thomas Geppert.
# License: GNU GPLv2.0


"""
BCC implementation of a systemd service that resumes suspended ZFS zpool disks
in parallel to reduce the latency of a zpool wakeup.

A disk resume event is detected via an eBPF kfunc probe on the kernel function
'sd_resume_power'. The probe places an event structure on a ring buffer which is
used for the communication with the user land Python process. The event
structure contains the sysfs inode number of the resuming device and a
timestamp of the call to 'sd_resume_power'.

The user land Python process waits for events on the ring buffer. If the inode
number of a resume event belongs to a zpool member disk, it identifies the pool
and resumes other suspended disks in the pool in parallel.

The Python process gets the zpool configuration from the 'zdb' command. To
associate the disk devices reported by 'zdb' with the inode numbers reported by
the eBPF program, it uses the path '/sys/block/sd*/../..' in sysfs.

On startup, the Python process does by default configure the Linux Runtime Power
Management for all zpool disks. This autoconfiguration can be customized and
also be disabled on the command line.

For spinning up other suspended disks in a zpool, the service makes a non
blocking 'os.open' call for each companion disk in the pool. The resume
operation caused by an 'os.open' call does of course also trigger the service
and without the capability to identify such self-inflicted events it would again
make an 'os.open' call for each of the other disks in the zpool. Thus, the
wake-up of a disk in a sleeping zpool with N disks would trigger N*(N-1)
'os.open' calls. Due to its quadratic nature, this could quick become an
unacceptable large number. To avoid this unnecessary proliferation of 'os.open'
calls, the service has to do some bookkeeping.

The central bookkeeping mechanism is a BPF_HASH map. This map can be read and
written from both sides, the eBPF program in the kernel and the Python process
in user space. When the Python process is triggered by the eBPF kernel probe, it
creates an entry in the BPF_HASH map for every disk device that it will resume
via an 'os.open' call. The eBPF program on the other side does check the map for
an entry of the device that caused a resume event and only triggers the Python
process if the device is not contained in the map. In case it finds the device
in the map, this means that a resume event caused by the Python process was
pending and therefore just deletes this entry from the map.

Another problem is caused by the fact that sometimes a zpool is not resumed
completely sequential and more than one zpool disk is resumed almost in
parallel. This does create multiple entries in the ring buffer which is used for
reporting a disk resume event from the eBPF program to the Python process. Each
of these entries invokes the callback function of the probe which needs to
identify the first of this series of resume callbacks. All resume callbacks
after the first can, and should, be ignored. To facilitate the identification, a
timestamp is included in the event structure that is written to the ring buffer.
The timestamp of the first disk resume event in a pool is stored by the Python
process and compared with the time code of later resume events. If the
difference is larger than 10**10 nano seconds (10 sec) the current event is
regarded as the first disk resume event of a new zpool wakeup. The time code of
this resume event then replaces the stored time code for this zpool and the
other disks of the pool are resumed. Any event whose difference is smaller than
10 sec is ignored in the Python process because it originated from a disk that
was resumed almost in parallel with the first one. The threshold value of 10 sec
was chosen because it is large enough to safely assume that it covers all disks
that were already resumed while the Python process performs its actions and
small enough to exclude, and thus identify, an intermediate suspension of the
zpool.

NOTE:
To resume the disks, a side effect of opening a device in read-write or
write-only mode is used. It is in fact the call to close the file descriptor
that wakes up the disk. Opening the device in read-only mode does not have this
side effect.
From the Linux standard C library 'open(2)' manpage:

   File access mode
       Unlike the other values that can be specified in flags, the access mode
       values O_RDONLY,  O_WRONLY,  and  O_RDWR  do  not specify  individual
       bits.  Rather, they define the low order two bits of flags, and are
       defined respectively as 0, 1, and 2.  In other words, the combination
       O_RDONLY | O_WRONLY is a logical error, and certainly does not have the
       same  meaning as O_RDWR.

       Linux  reserves  the special, nonstandard access mode 3 (binary 11) in
       flags to mean: check for read and write permission on the file and return
       a file descriptor that can't be used for reading or writing.  This
       nonstandard access mode is used by some Linux drivers to return a file
       descriptor that is to be used only for device-specific ioctl(2)
       operations.

The mentioned access mode combination of 'O_WRONLY | O_RDWR' (binary 11) could
be used to avoid the side effect and send ioctl commands to the device without
waking it up. However, since the intention is to resume the disk, we make use of
the side effect and avoid the hassle to issue a 'START STOP UNIT' ioctl.
"""


import argparse
import logging
import logging.handlers
import math
import os
import os.path
import platform
import re
import signal
import subprocess
import sys
import time

from bcc import BPF
from ctypes import c_ulonglong
from systemd import daemon
from typing import Optional


# Configurable parameters.
CONFIG_FILE = "/etc/zfs/zpool.cache"
LOG_FILE = '/var/log/zolspinup.log'
REPORT_FILE = 'var/log/spinstate.report'
ZDB = "/usr/sbin/zdb"


_log_sddisk =logging.getLogger('zolspinup.sddisk')
_log_sddisk.addHandler(logging.NullHandler())
_log_zprpmmgr =logging.getLogger('zolspinup.zpoolrpmmanager')
_log_zprpmmgr.addHandler(logging.NullHandler())
_log_spnrpt =logging.getLogger('spinreport')
_log_spnrpt.addHandler(logging.NullHandler())


class SdDisk():
    def __init__(self, blk_dev: str, pool: str, legacy_spin_ctrl=False) -> None:
        if not blk_dev.startswith("sd"):
            err_msg = "Device {0} is not a SCSI or SATA disk.".format(blk_dev)
            _log_sddisk.critical(err_msg)
            raise ValueError(err_msg)
        self.__blk_dev = blk_dev
        self.__pool = pool
        self.__dev_path = os.path.realpath("/sys/block/" + blk_dev + "/../..")
        if legacy_spin_ctrl:
            self.__spin_ctrl_file = (self.__dev_path + "/scsi_disk/" +
                                     os.path.basename(self.__dev_path) +
                                     "/manage_start_stop")
        else:
            self.__spin_ctrl_file = (self.__dev_path + "/scsi_disk/" +
                                     os.path.basename(self.__dev_path) +
                                     "/manage_runtime_start_stop")
        try:
            self.__ino: int = os.stat(self.__dev_path).st_ino
        except Exception as e:
            _log_sddisk.critical(
                "Cannot get sysfs inode number of device path %s.",
                self.__dev_path
            )
            raise e
        try:
            rot_file = os.path.realpath("/sys/block/" + blk_dev +
                                        "/queue/rotational")
            f_rot = os.open(rot_file, os.O_RDONLY)
            self.__is_rotational = True if int(os.read(f_rot, 1)) else False
        except Exception as e:
            _log_sddisk.critical(
                "Failed to get rotational status of device %s.", blk_dev)
            _log_sddisk.critical(
                "Failed reading file %s due to the following exception.",
                rot_file
            )
            _log_sddisk.critical(repr(e))
            raise e
        else:
            os.close(f_rot)

    @property
    def blk_dev(self) -> str:
        return self.__blk_dev

    @property
    def pool(self) -> str:
        return self.__pool

    @property
    def ino(self) -> int:
        return self.__ino
                
    @property
    def is_rotational(self) -> bool:
        return self.__is_rotational

    @property
    def rpm_status(self) -> str:
        runtime_file = self.__dev_path + "/power/runtime_status"
        try:
            f_runtime = os.open(runtime_file, os.O_RDONLY)
            runtime_stat = os.read(f_runtime, 11).decode("utf-8").strip()
            os.close(f_runtime)
        except Exception as e:
            _log_sddisk.error(
                "Failed to get power status for device %s.", self.__blk_dev)
            _log_sddisk.error(
                "Failed reading file %s due to the following exception.",
                runtime_file
            )
            _log_sddisk.error(repr(e))
            raise e
        return runtime_stat
    
    @property
    def rpm_delay(self) -> int:
        delay_file = self.__dev_path + "/power/autosuspend_delay_ms"
        try:
            f_delay = os.open(delay_file, os.O_RDONLY)
            delay = os.read(f_delay, 256).decode("utf-8").strip()
            os.close(f_delay)
        except Exception as e:
            _log_sddisk.error(
                "Failed to get autosuspend delay for device %s", self.__blk_dev)
            _log_sddisk.error(
                "Failed reading file %s due to the following exception.",
                delay_file
            )
            _log_sddisk.error(repr(e))
            raise e
        return math.floor(int(delay) / 1000 + 0.5)
    @rpm_delay.setter
    def rpm_delay(self, delay: int) -> None:
        if not isinstance(delay, int):
            raise TypeError("RPM autosuspend delay value must be an integer.")
        delay_file = self.__dev_path + "/power/autosuspend_delay_ms"
        try:
            f_delay = os.open(delay_file, os.O_WRONLY)
            os.write(f_delay, str(delay * 1000).encode("utf-8"))
            os.close(f_delay)
        except Exception as e:
            _log_sddisk.error(
                "Failed to set autosuspend delay for device %s to %d seconds.",
                self.__blk_dev, delay
            )
            _log_sddisk.error(
                "Failed writing file %s due to the following exception.",
                delay_file
            )
            _log_sddisk.error(repr(e))
            raise e

    @property
    def rpm_controlled(self) -> bool:
        ctrl_file = self.__dev_path + "/power/control"
        try:
            f_ctrl = os.open(ctrl_file, os.O_RDONLY)
            ctrl_stat = True if os.read(f_ctrl, 5) == b'auto\n' else False
            os.close(f_ctrl)
        except Exception as e:
            _log_sddisk.error(
                "Failed to get runtime power management status for device %s.",
                self.__blk_dev
            )
            _log_sddisk.error(
                "Failed reading file %s due to the following exception.",
                ctrl_file
            )
            _log_sddisk.error(repr(e))
            raise e
        return ctrl_stat
    @rpm_controlled.setter
    def rpm_controlled(self, do_ctrl: bool) -> None:
        if not isinstance(do_ctrl, bool):
            raise TypeError("RPM control value must be a boolean.")
        ctrl_str = b'auto' if do_ctrl else b'on'
        ctrl_file = self.__dev_path + "/power/control"
        try:
            f_ctrl = os.open(ctrl_file, os.O_WRONLY)
            os.write(f_ctrl, ctrl_str)
            os.close(f_ctrl)
        except Exception as e:
            _log_sddisk.error(
                "Failed to enable runtime power management for device %s.",
                self.__blk_dev
            )
            _log_sddisk.error(
                "Failed writing file %s due to the following exception.",
                ctrl_file
            )
            _log_sddisk.error(repr(e))
            raise e

    @property
    def spin_controlled(self) -> bool:
        try:
            f_ststp = os.open(self.__spin_ctrl_file, os.O_RDONLY)
            spindown_ctrl_stat = True if int(os.read(f_ststp, 1)) else False
            os.close(f_ststp)
        except Exception as e:
            _log_sddisk.error(
                "Failed to get kernel spindown "
                "management setting for device %s.", self.__blk_dev
            )
            _log_sddisk.error(
                "Failed reading file %s due to the following exception.",
                self.__spin_ctrl_file
            )
            _log_sddisk.error(repr(e))
            raise e
        return spindown_ctrl_stat
    @spin_controlled.setter
    def spin_controlled(self, do_ctrl: bool) -> None:
        if not isinstance(do_ctrl, bool):
            raise TypeError("Spin control value must be a boolean.")
        try:
            f_ststp = os.open(self.__spin_ctrl_file, os.O_WRONLY)
            os.write(f_ststp, b'1')
            os.close(f_ststp)
        except Exception as e:
            _log_sddisk.error(
                "Failed to enable kernel spindown management for device %s.",
                self.__blk_dev
            )
            _log_sddisk.error(
                "Failed writing file %s due to the following exception.",
                self.__spin_ctrl_file
            )
            _log_sddisk.error(repr(e))
            raise e


# We difine a meta class which assures that only one instance is ever created.
class Singleton(type):
    def __init__(self, *args, **kwargs):
        self.__instance = None
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        if self.__instance is None:
            self.__instance = super().__call__(*args, **kwargs)
        return self.__instance


class ZpoolRpmManager(metaclass=Singleton):
    """
    Class holding the zpool configuration with methods to:
        - get the current zpool configuration
        - configure the Linux Runtime Power Management
    """

    eBPF_resume_monitor = """
    #include <linux/device.h>
    #include <linux/kobject.h>
    #include <linux/kernfs.h>

    BPF_RINGBUF_OUTPUT(resume_probe, 1);
    BPF_HASH(skip_map);

    struct resume_event {
        u64 ino;
        u64 ts;
    };

    KFUNC_PROBE(sd_resume_runtime, struct device *dev)
    {
        u64 *do_skip;
        u64 delta;
        u64 ino = dev->kobj.sd->id;
        u64 ts = bpf_ktime_get_ns();

        do_skip = skip_map.lookup(&ino);
        if (do_skip) {
            delta = ts - *do_skip;
            skip_map.delete(&ino);
            if (delta < 10000000000) {
                return 0;
            }
        }
        struct resume_event *dev_info = resume_probe.ringbuf_reserve(
            sizeof(struct resume_event));
        if (!dev_info) {
            return 0;
        }
        dev_info->ino = ino;
        dev_info->ts = ts;
        resume_probe.ringbuf_submit(dev_info, BPF_RB_FORCE_WAKEUP);
        return 0;
    }
    """

    eBPF_suspend_monitor = """
    BPF_RINGBUF_OUTPUT(suspend_probe, 1);

    struct suspend_event {
        u64 ino;
    };

    KFUNC_PROBE(sd_suspend_runtime, struct device *dev)
    {
        u64 ino = dev->kobj.sd->id;

        struct suspend_event *dev_info = suspend_probe.ringbuf_reserve(
            sizeof(struct suspend_event));
        if (!dev_info) {
            return 0;
        }
        dev_info->ino = ino;
        suspend_probe.ringbuf_submit(dev_info, BPF_RB_FORCE_WAKEUP);
        return 0;
    }
    """

    # This is used to parse the 'zdb -C' output.
    pool_pattern = re.compile(r'(^[a-zA-Z].+?):')
    path_pattern = re.compile(r'^\s+path:\s\'(/dev/.+?)\'')

    def __init__(self, autosuspend_delay=3600,
                 noconfig=True, do_report=False) -> None:
        self.__autosuspend_delay = autosuspend_delay
        self.__noconfig = noconfig
        self.__do_report = do_report
        self.__zpools: dict[str, list[SdDisk]] = {}
        self.__rpm_pools: dict[str, list[SdDisk]] = {}
        self.__rpm_inodes: dict[int, SdDisk] = {}
        self.__last_wakeup: dict[str, int] = {}
        # The name of the file in sysfs controlling the runtime spindown
        # of disks was changed between kernel release 6.4 and 6.5.
        major_release, minor_release = platform.uname().release.split('.')[0:2]
        if int(major_release) >= 6 and int(minor_release) >= 5:
            _log_zprpmmgr.info(
                "Linux kernel version %s.%s, using "
                "'manage_runtime_start_stop' spindown indicator.",
                major_release, minor_release
            )
            self.__legacy_spin_ctrl = False
        else:
            _log_zprpmmgr.info(
                "Linux kernel version is %s.%s, using "
                "'manage_start_stop' as spindown control indicator.",
                major_release, minor_release
            )
            self.__legacy_spin_ctrl = True
        self.__last_config_update = self.__get_zpool_config()
        self.__config_rpm()
        self.__get_rpm_config()
        self.__eBee = None

    def __get_zpool_config(self) -> float:
        """
        Get the current zpool configuration of rotational disks.

        We need the zpool configuration to map disk devices to pools but we
        cannot get it via the zpool command because it would query the pools and
        block on sleeping disks. Therefore we use the zdb command to get the
        cached zpool configuration.
        """
        update_time = time.time()
        try:
            config_text = subprocess.run(
                [ZDB, '-C'], capture_output=True, check=True, text=True).stdout
        except Exception as e:
            _log_zprpmmgr.error("Failed to execute the 'zdb' command.")
            _log_zprpmmgr.error(
                "The 'subprocess.run' command raised the following exception.")
            _log_zprpmmgr.error(repr(e))
            return
        self.__zpools = {}
        for line in config_text.splitlines():
            # Find the start of a zpool description block and get the pool name.
            if match := ZpoolRpmManager.pool_pattern.search(line):
                pool = match.group(1)
                self.__zpools[pool] = []
            # Find the block device paths of the physical vdevs in this pool.
            elif match := ZpoolRpmManager.path_pattern.search(line):
                # We extract the block device name of the whole disk...
                blk_dev = os.path.realpath(
                    match.group(1)).rstrip("0123456789").rsplit('/',1)[1]
                # We don't need to bother with NVME disks.
                if blk_dev.startswith("nvme"):
                    continue
                try:
                    disk = SdDisk(blk_dev=blk_dev, pool=pool,
                                  legacy_spin_ctrl=self.__legacy_spin_ctrl)
                except Exception:
                    _log_zprpmmgr.critical(
                        "Failed to identify device %s.", blk_dev)
                    _log_zprpmmgr.critical(
                        "Device %s will be excluded from spin management.",
                        blk_dev
                    )
                    continue
                # We only deal with rotational disks.
                if disk.is_rotational:
                    self.__zpools[pool].append(disk)
        return update_time

    def __config_rpm(self) -> None:
        if self.__noconfig:
            _log_zprpmmgr.info(
                "Configuration of autosuspend settings "
                "disabled, will keep settings untouched."
            )
        else:
            _log_zprpmmgr.info(
                "Configuring autosuspend to spindown after "
                "%d seconds idle time for all managed disks.",
                self.__autosuspend_delay
            ) 
            for pool, disks in self.__zpools.items():
                for disk in disks:
                    try:
                        disk.spin_controlled = True
                        disk.rpm_delay = self.__autosuspend_delay
                        disk.rpm_controlled = True
                    except Exception:
                        _log_zprpmmgr.error(
                            "Autoconfiguration failed for device %s.",
                            disk.blk_dev
                        )

    def __get_rpm_config(self) -> None:
        # Only keep disks which are start stop managed by the kernel.
        rpm_pools = {}
        for pool, disks in self.__zpools.items():
            managed_disks = []
            for disk in disks:
                try:
                    if disk.spin_controlled:
                        managed_disks.append(disk)
                except Exception:
                    _log_zprpmmgr.critical(
                        "Device %s will be excluded from spin management.",
                        disk.blk_dev
                    )
            rpm_pools[pool] = managed_disks
        # A pool needs at least 2 disks to spin something up in parallel.
        self.__rpm_pools = {}
        for pool, disks in rpm_pools.items():
            if len(disks) > 1:
                self.__rpm_pools[pool] = disks
        # Generate a sysfs inode number to zpool mapping to identify
        # disks reported by the BPF probe that require an action.
        self.__rpm_inodes = {disk.ino:disk
                             for disks in self.__rpm_pools.values()
                                for disk in disks}
        # For DEBUG show the used pool configurations.
        _log_zprpmmgr.debug("Using the following zpool configuration.")
        for pool, disks in self.__rpm_pools.items():
            _log_zprpmmgr.debug("    zpool: %s", pool)
            for disk in disks:
                _log_zprpmmgr.debug(
                    "        disk: %s with inode: %d", disk.blk_dev, disk.ino)
    
    def __handle_resume_event(self, ctx, data, size) -> None:
        resume_event = self.__eBee['resume_probe'].event(data)
        ino: int = resume_event.ino
        ts: int = resume_event.ts
        # We update the zpool configuration if the cache file has changed.
        if os.path.getmtime(CONFIG_FILE) > self.__last_config_update:
            _log_zprpmmgr.info("Updating zpool configuration.")
            self.update_config()
        if ino in self.__rpm_inodes:
            pool = self.__rpm_inodes[ino].pool
            if self.__do_report:
                t = str(int(time.time()))
                _log_spnrpt.info(
                    f'{t},{pool},{self.__rpm_inodes[ino].blk_dev},1')
            if (
                pool not in self.__last_wakeup or
                ts - self.__last_wakeup[pool] > 10000000000
                ):
                self.__last_wakeup[pool] = ts
                pooldisks = self.__rpm_pools[pool]
                disks2spinup = [ disk for disk in pooldisks if disk.ino != ino ]
                _log_zprpmmgr.info(
                    "Wakeup of disk: %s with inode: %d "
                    "in zpool %s with timestamp: %d.",
                    self.__rpm_inodes[ino].blk_dev, ino, pool, ts
                )
                _log_zprpmmgr.debug(
                    "Spinning up remaining suspended pool devices.")
                for disk in disks2spinup:
                    try:
                        if disk.rpm_status[0] == 's':
                            _log_zprpmmgr.debug(
                                "    Starting disk: %s with inode: %d",
                                disk.blk_dev, disk.ino
                            )
                            self.__eBee["skip_map"][
                                c_ulonglong(disk.ino)
                            ] = c_ulonglong(ts)
                            try:
                                # See the NOTE in the opening comment regarding
                                # the mechanism used to resume a disk.
                                fd = os.open("/dev/" + disk.blk_dev,
                                             os.O_NONBLOCK | os.O_RDWR)
                                os.close(fd)
                            except Exception as e:
                                _log_zprpmmgr.error(
                                    "Failed to open device %s.", disk.blk_dev)
                                _log_zprpmmgr.error(
                                    "The 'os.open' call issued to start the "
                                    "device raised the following exception."
                                )
                                _log_zprpmmgr.error(repr(e))
                            if self.__do_report:
                                _log_spnrpt.info(f'{t},{pool},{disk.blk_dev},1')
                    except Exception as e:
                        _log_zprpmmgr.error(
                            "Failed to get power status of device %s.",
                            disk.blk_dev
                        )
            else:
                _log_zprpmmgr.debug(
                    "    Ignoring disk: %s with inode: %d, "
                    "already started at timestamp %d",
                    self.__rpm_inodes[ino].blk_dev, ino, ts
                )

    def __handle_suspend_event(self, ctx, data, size) -> None:
        suspend_event = self.__eBee['suspend_probe'].event(data)
        ino: int = suspend_event.ino
        # We update the zpool configuration if the cache file has changed.
        if os.path.getmtime(CONFIG_FILE) > self.__last_config_update:
            _log_zprpmmgr.info("Updating zpool configuration.")
            self.update_config()
        if ino in self.__rpm_inodes:
            pool = self.__rpm_inodes[ino].pool
            t = str(int(time.time()))
            _log_spnrpt.info(
                f'{t},{pool},{self.__rpm_inodes[ino].blk_dev},0')

    def update_config(self, autosuspend_delay: Optional[int]=None,
                            noconfig: Optional[bool]=None) -> None:
        if autosuspend_delay is not None:
            if isinstance(autosuspend_delay, int):
                self.__autosuspend_delay = autosuspend_delay
            else:
                _log_zprpmmgr.error(
                    "Invalid type %s of RPM autosuspend delay.",
                    type(autosuspend_delay)
                )
                _log_zprpmmgr.error(
                    "Autosuspend delay value must be an integer.")
                _log_zprpmmgr.error("Not updating RPM autosuspend delay")
        if noconfig is not None:
            if isinstance(noconfig, bool):
                self.__noconfig = noconfig
            else:
                _log_zprpmmgr.error(
                    "Invalid type %s of 'noconfig' parameter.", type(noconfig))
                _log_zprpmmgr.error("'noconfig' must be a boolean value.")
                _log_zprpmmgr.error("Not updating 'noconfig' parameter")     
        self.__last_config_update = self.__get_zpool_config()
        self.__config_rpm()
        self.__get_rpm_config()

    def rpm_stat(self) -> str:
        """
        Return the runtime power management status of all zpool rotational disks
        in a formatted string. The information is taken from sysfs without
        changing the power state of any disk.
        """
        pool_stat = "Runtime power management status "\
                    "of rotational zpool disks:"
        for pool, disks in self.__zpools.items():
            if not disks: continue
            pool_stat += "\n\n" + pool + "\n\tDISK   STATUS     RPM  SPDN  "\
                "AUTOSUSPEND-DELAY [s]"
            for disk in disks:
                try:
                    spindown_ctrl_stat = "yes" if disk.spin_controlled else "no"
                except Exception:
                    spindown_ctrl_stat = "NA"
                try:
                    delay_stat = disk.rpm_delay
                except Exception:
                    delay_stat = "NA"
                try:
                    ctrl_stat = "yes" if disk.rpm_controlled else "no"
                except Exception:
                    ctrl_stat = "NA"
                try:
                    runtime_stat = disk.rpm_status
                except Exception:
                    runtime_stat = "NA"
                pool_stat += (
                    "\n\t{0:6} {1:10} {2:4} {3:5} {4}"
                    .format(disk.blk_dev, runtime_stat,
                            ctrl_stat, spindown_ctrl_stat, delay_stat)
                )
        return pool_stat

    def start_monitor(self) -> None:
        if self.__eBee == None:
            if self.__do_report:
                eBPF_program = (ZpoolRpmManager.eBPF_resume_monitor +
                                ZpoolRpmManager.eBPF_suspend_monitor)
                self.__eBee = BPF(text=eBPF_program)
                self.__eBee['resume_probe'].open_ring_buffer(
                    self.__handle_resume_event
                )
                self.__eBee['suspend_probe'].open_ring_buffer(
                    self.__handle_suspend_event
                )
            else:
                eBPF_program = ZpoolRpmManager.eBPF_resume_monitor
                self.__eBee = BPF(text=eBPF_program)
                self.__eBee['resume_probe'].open_ring_buffer(
                    self.__handle_resume_event
                )
        else:
            _log_zprpmmgr.warning("The eBPF monitor program is already loaded.")

    def handle_events(self) -> None:
        if self.__eBee is not None:
            self.__eBee.ring_buffer_poll()
        else:
            _log_zprpmmgr.error("Failed polling for wakeup events.")
            _log_zprpmmgr.error("The monitor has to be startet first.")
            raise RuntimeError(
                "No eBPF monitor. Failed polling for wakeup events.")



if __name__ == "__main__":

    # Check the most basic requirements.
    if platform.system() != "Linux":
        print(
            "This program requires the Linux operatin system. "
            "Terminating.", file=sys.stderr
        )
        sys.exit(1)
    if not os.access(ZDB, os.X_OK):
        print(
            "Cannot execute required 'zdb' utility under "
            "path {0}. Terminating.".format(ZDB), file=sys.stderr
        )
        daemon.notify("STOPPING=1")
        sys.exit(1)

    # We have currently implemented the commands:
    # - rpmstat: print the RPM settings of all zpool rotational disks to stdout.
    # - zolspinup: spin up all disks of a zpool when the first disk resumes.
    command_name = os.path.basename(sys.argv[0])
    # The 'rpmstat' command simply does its work and exits.
    if command_name == "rpmstat":
        rpm_mgr = ZpoolRpmManager()
        print(rpm_mgr.rpm_stat())
        exit(0)
    # The zolspinup command will run as a service and setup logging.
    elif command_name == "zolspinup":
        logfile = os.path.realpath(LOG_FILE)
    else:
        print(
            "Functionality for command {0} is not implemented."
            .format(command_name), file=sys.stderr
        )
        exit(1)

    # Check that we can write the specified logfile.
    if  (
            (
                os.access(logfile, os.F_OK) and
                not os.access(logfile, os.W_OK)
            ) or
            (
                not os.access(logfile, os.F_OK) and
                not os.access(os.path.dirname(logfile), os.W_OK)
            )
        ):
        print(
            "Cannot write log file {0}. Terminating Service."
            .format(logfile), file=sys.stderr
        )
        daemon.notify("STOPPING=1")
        sys.exit(1)

    # Parse the command line.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-l", "--loglevel", type=int, default=logging.WARNING,
        help="logging level, integer 10:DEBUG, 20:INFO, "
            "30:WARNING (default), 40:ERROR, 50:CRITICAL"
    )
    parser.add_argument(
        "-d", "--delay", type=int, default=3600, help=
        "autosuspend delay in seconds, default: 3600 s (1 hour), minimum: 60 s"
    )
    parser.add_argument(
        "-n", "--noconfig", action='store_true',
        help="do not autoconfigure disk runtime power management settings"
    )
    parser.add_argument(
        "-r", "--report", action='store_true',
        help="write spin state changes of disks to a report file"
    )
    args = parser.parse_args()
    log_level: int = args.loglevel
    # The log_level has to be within the interval from DEBUG to CRITICAL.
    if log_level < logging.DEBUG or log_level > logging.CRITICAL:
        log_level = logging.WARNING
        adjusted_loglevel = True
    else:
        adjusted_loglevel = False
    autosuspend_delay: int = args.delay
    # Take care that the autosuspend delay is not smaller than 60 seconds.
    if autosuspend_delay < 60:
        autosuspend_delay = 60
        adjusted_delay = True
    else:
        adjusted_delay = False
    noconfig: bool = args.noconfig
    do_report: bool = args.report

    # Setup logging.
    logger = logging.getLogger('zolspinup')
    logger.setLevel(log_level)
    logger.propagate = False
    # We create a rotating file logger with a max of 10 logfiles of 1MB size.
    log_handler = logging.handlers.RotatingFileHandler(
        logfile,
        maxBytes=1048576,
        backupCount=10
    )
    log_formatter = logging.Formatter(
        "%(levelname)-8s:%(asctime)s: %(message)s")
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)
    # Start logging.
    logger.info(
        "Service starting up and logging to file %s with loglevel %d.",
        logfile, log_level
    )
    print(
        "Service starting up and logging to file {0} with loglevel {1}."
        .format(logfile, log_level), file=sys.stderr
    )
    if adjusted_loglevel:
        logger.warning(
            "Invalid loglevel value %d on command line was "
            "adjusted to default value 30 (WARNING).", args.loglevel
        )
    if adjusted_delay:
        logger.warning(
            "Invalid autosuspend delay value %d on command "
            "line was adjusted to minimum value 60.", args.delay
        )

    # This is used to log systemd notification.
    def notify_systemd(msg) -> None:
        if (sysd_notify := daemon.notify(msg)) > 0:
            logger.debug("Notification of service manager succeeded.")
        elif sysd_notify == 0:
            logger.warning("Could not send notification to service manager.")
        else:
            logger.error("Failed to notify service manager.")

    # Configure signal handling.
    class UpdateConfigException(Exception):
        """Exception is raised when the SIGHUP signal is received."""
        pass
    def reload_config(signum, frame) -> None:
        logger.info("Received SIGHUP signal.")
        raise UpdateConfigException
    def shutdown(signum, frame) -> None:
        logger.info("Received SIGTERM signal.")
        raise KeyboardInterrupt
    signal.signal(signal.SIGHUP, reload_config)
    signal.signal(signal.SIGTERM, shutdown)

    # Check that the zpool.cache file is accessible.
    if not os.access(CONFIG_FILE, os.R_OK):
        logger.critical(
            "Cannot access the zpool cache file under path %s. "
            "Terminating Service.", CONFIG_FILE
        )
        print(
            "Cannot access the zpool cache file under path {0}. "
            "Terminating Service.".format(CONFIG_FILE), file=sys.stderr
        )
        notify_systemd("STOPPING=1")
        sys.exit(1)

    # Setup reporting if requested on the command line.
    if do_report:
        reportfile = os.path.realpath(REPORT_FILE)
        # Check that we can write the specified reportfile.
        if  (
                (
                    os.access(reportfile, os.F_OK) and
                    not os.access(reportfile, os.W_OK)
                ) or
                (
                    not os.access(reportfile, os.F_OK) and
                    not os.access(os.path.dirname(reportfile), os.W_OK)
                )
            ):
            logger.critical(
                "Cannot write report file %s. Terminating Service.", reportfile)
            print(
                "Cannot write report file {0}. Terminating Service."
                .format(reportfile), file=sys.stderr
            )
            notify_systemd("STOPPING=1")
            sys.exit(1)
        else:
            logger.info("Writing spin change report to file %s.", reportfile)
        
        # Setup reporting.
        reporter = logging.getLogger('spinreport')
        reporter.setLevel(logging.INFO)
        reporter.propagate = False
        # Use a rotating file logger with a max of 10 reportfiles of 1MB size.
        report_handler = logging.handlers.RotatingFileHandler(
            reportfile,
            maxBytes=1048576,
            backupCount=10
        )
        report_formatter = logging.Formatter(
            "%(message)s")
        report_handler.setFormatter(report_formatter)
        reporter.addHandler(report_handler)

    # Gather the information about which disks to manage.
    logger.info("Reading zpool configuration.")
    spinup_mgr = ZpoolRpmManager(
        autosuspend_delay=autosuspend_delay,
        noconfig=noconfig, do_report=do_report)

    # Initialize the spinup monitor.
    logger.info("Starting eBPF monitoring probe.")
    spinup_mgr.start_monitor()
    logger.info("Service initialization completed.")
    print("Service initialization completed.", file=sys.stderr)
    notify_systemd("READY=1")
    # Loop indefinitely polling the ringbuffer.
    while True:
        try:
            spinup_mgr.handle_events()
        except UpdateConfigException:
            logger.info("Forcing update of zpool configuration.")
            print("Forcing update of zpool configuration.", file=sys.stderr)
            notify_systemd("RELOADING=1")
            spinup_mgr.update_config()
            logger.info("Finished update of zpool configuration.")
            print(
                "Finished update of zpool configuration.", file=sys.stderr)
            notify_systemd("READY=1")
        except KeyboardInterrupt:
            logger.info("Terminating service.")
            print("Terminating service.", file=sys.stderr)
            notify_systemd("STOPPING=1")
            sys.exit()
