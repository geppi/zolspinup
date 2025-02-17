# zolspinup
The ZFS on Linux zpool disk spin-up daemon  
is an implementation of the original OpenSolaris/Illumos based [zpool_spinupd](https://github.com/geppi/zpool_spinup) for Linux.

It is implemented as a systemd service that monitors resume events of ZFS zpool disks and executes an asynchronous start command in parallel to all other disks in the same zpool. This dramatically improves the latency of a sleeping zpool.

## Motivation
The power consumption of a rotational storage device can be substantially reduced by spinning down the disk platters when the device is not used. While disks in an enterprise environment or a data center are pretty much in use 24x7, the disks in a SOHO environment often idle in the night and during non office hours.  
This offers the potential to put disks into a low power, non spinning state for longer periods. The trade-off is an increased latency when accessing the device due to the time it takes to spin up the disk. The latter is exacerbated if multiple disks have to spin up sequentially before a request can be serviced.  
Unfortunately this is exactly what happens when requesting data from a ZFS zpool with sleeping disks. The typical spin-up time of a single disk is in the order of about 10 seconds which leads to spin-up times of even mid sized zpools in the order of minutes. This is an unacceptable large latency which frequently leads to timeouts of the requesting applications.

## Installation
The _zolspinup_ service requires the [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc) and a recent version of **Python** (development was done with python3.11). Most Linux distributions provide packages for these components. For **BCC** in particular, see the [installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md). On top of the Python standard library also the [**python-systemd**](https://github.com/systemd/python-systemd) package is required.

As an example, on a Debian system the required packages can be installed with:
```
apt-get install -y bpfcc-tools libbpfcc python3-bpfcc python3-systemd
```

For setting up the service execute these commands as root:
```
cp zolspinup.service /etc/systemd/system
cp zolspinup.py /usr/local/sbin/zolspinup
systemctl daemon-reload
systemctl enable zolspinup
systemctl start zolspinup
```

## Operation
The systemd unit configuration file _zolspinup.service_ expects the daemon executable to be located in '/usr/local/sbin' and starts it without any command line options. You can customize the executable location and command line parameters on the 'ExecStart' line of the service configuration file.

When running, the service logs into the file '/var/log/zolspinup.log' with log level _WARNING_, i.e. warning messages, error messages and critical errors are logged.

By default, the service will configure the Linux Runtime Power Management to suspend and spin down every rotational disk that is a member of a zpool after one hour idle time. It then monitors these disks to detect when a disk is resumed by the Linux Runtime Power Management.

In case of a disk resume event, the service causes all other disks which are members of the same zpool to spin up in parallel, thus it minimizes the latency of a sleeping zpool to the spin-up time of a single disk.

Runtime changes to the configuration of zpools are automatically recognized. In addition the service can be triggered to update the configuration information by sending it the _SIGHUP_ signal with `killall -SIGHUP zolspinup`. However, this is only required if the `-n` command line option was given (see below) and the Linux Runtime Power Management settings were changed.

 ## Customization
 ### Command line parameters
The usage of the zolspinup command is:
```
zolspinup [-h] [-d DELAY] [-l LOGLEVEL] [-n] [-r]

options:
  -h, --help            show this help message and exit
  -l LOGLEVEL, --loglevel LOGLEVEL
                        logging level, integer 10:DEBUG, 20:INFO, 30:WARNING (default), 40:ERROR, 50:CRITICAL
  -d DELAY, --delay DELAY
                        autosuspend delay in seconds, default: 3600 s (1 hour), minimum: 60 s
  -n, --noconfig        do not autoconfigure disk runtime power management settings
  -r, --report          write spin state changes of disks to a report file
```
#### Logging
To change the log level use the `-l` command line option and provide an integer not smaller than 10 and not bigger than 50. The default log level is _WARNING_ but even with log level _DEBUG_, i.e. integer value 10, the logging is not too verbose. The _INFO_ log level does report when a zpool is resumed and which disk triggered it while the _DEBUG_ log level provides detailed information about which disks were resumed by the service.

#### Autosuspend delay
On service startup, the daemon identifies all rotational disks that are members of a zpool, i.e. non pool disks and SSDs are excluded. It then configures the Linux Runtime Power Management to suspend and spin down these disks after one hour idle time. This delay can be changed with the `-d` command line option. The delay has to be specified in seconds, i.e. the standard delay of one hour is `-d 3600`.

#### No RPM autoconfig
In case the automatic configuration of the Linux Runtime Power Management is not desired, e.g. because different autosuspend delays should be used for different pools or some pools should even not be suspended at all, it is possible to disable the automatic configuration with the `-n` command line option.  
In that case the Linux Runtime Power Management has to be configured manually for each disk by some other means.

#### Report file
The service can report all suspend and resume events of monitored zpool disks when the `-r` command line option is provided. It will then write one line per disk event into the file '/var/log/spinstate.report'. Each line contains the time of the event in seconds since the beginning of the epoch, the zpool name, the disk device name and the event type as comma separated values. The event type is '0' for suspend events and '1' for resume events.

### Other customization parameters
The _zolspinup_ service is implemented in Python and contains a few parameters at the beginning of the code right after the _import_ statements for easy customization of some potentially system dependent variables. These are:
|             |   |
| ----------- | - |
| LOG_FILE    | _the path of the log file_       |
| REPORT_FILE | _the path of the report file_    |
| ZDB         | _the path of the zdb command_    |
| CONFIG_FILE | _the path of the ZFS cache file_ |

Except for the _LOG_FILE_ parameter which can be used to customize the location of the logging output, it should be rarely required to modify the other parameters.

## Optimization
When starting to use the _zolspinup_ service on a system, it is recommended to adapt the autosuspend delay value to the particular system operation. The goal is to maximize the time that disks are in the suspended state while minimizing the number of spin-up operations per day. The sweet spot of this trade-off is determined by the usage pattern of the system. If the delay is too short, it will frequently happen that disks go to sleep and have to be woken up short after. If the delay is too long, disks might rarely or never go to sleep. This is a general problem of runtime power management but even more severe with rotational disk devices due to their large latency.

For the initial analysis, it will help to set the log level of the _zolspinup_ service to _INFO_, i.e. 20. The default log level of _WARNING_ will not report any spin-up operations and leave the log file completely empty as long as the service operates normal. With log level _INFO_ every detected disk resume event will be reported, while log level _DEBUG_ will in addition also report which disks were resumed by the service in cause of the event.

To enable a more sophisticated analysis the service can be configured to write a report file by providing the `-r` command line parameter.

The default autosuspend delay setting of one hour (3600 s) has proven to be a good general starting point for SOHO environments.

Unfortunately, contrary to OpenSolaris/Illumos, on Linux it is not possible for the _zolspinup_ service to identify and report the process that triggered the resume operation of a disk (for details, see Implementation).

A candidate that frequently wakes up sleeping disks on Linux distributions is **_smartd_** of _smartmontools_, which checks the disks on a regular interval, e.g. on Debian by default every 30 minutes. It is currently not possible to prevent the disk wake-up by configuring the _POWERMODE_ check of smartd because it does not check the runtime status of the disk in _sysfs_ but executes the ATA '_CHECK POWER MODE_' command to retrieve the power mode directly from the disk (see this [issue](https://github.com/smartmontools/smartmontools/issues/229) in _smartmontools_). Currently, the only workaround is to change the check interval of _smartd_ via its `-i` command line option in the systemd service file of _smartd_, e.g. with `-i 86400` to an interval of one day.

## Implementation
The basic concept is similar to the implementation of the original OpenSolaris/Illumos based [zpool_spinupd](https://github.com/geppi/zpool_spinup). Instead of a _Dtrace_ Function Boundary Tracing (_FBT_) provider an _eBPF_ kernel probe is used to get notified when a disk device is resumed. Also the _bpftrace_ utility on Linux would in the meantime provide all the functionality required to port the OpenSolaris/Illumos code in a pretty straight forward way. Unfortunately, a peculiarity of how asynchronous disk device access is implemented in the Linux kernel is creating a major obstacle for this easy approach.

Asynchronous device access is done in the kernel by putting a work item, that completely describes the asynchronous execution context, on a _workqueue_. These work items are then processed asynchronously by kernel worker threads. However, the process-ID under which a work item is executed is therefore not the ID of the process that initiated the device access but the process-ID of the _kworker_ thread. While the information about the executing _kworker_ is perfectly available in the context of the kernel probe instrumented by the _bpftrace_ program, there is no way to trace it back to the process that caused the work item on the _workqueue_.

The immediate consequence of this is, that the service under Linux can no longer identify and report the process responsible for the wake-up of a sleeping zpool which would be extremely helpful in the optimization process. The only information it could provide is the _kworker_ responsible for a resume operation, but this is too generic to draw a conclusion about the identity of the originator application.

However, the lack of information about the originator does not only make optimization harder, it also makes it impossible for the service to differentiate between a disk resume operation that was caused by itself or by some other application. For spinning up other suspended disks in a zpool, the service makes a non blocking _os.open_ call for each companion disk in the pool. The resume operation caused by an _os.open_ call does of course also trigger the service and without the capability to identify such self-inflicted events it would again make an _os.open_ call for each of the other disks in the zpool. Thus, the wake-up of a disk in a sleeping zpool with N disks would trigger N*(N-1) _os.open_ calls. Due to its quadratic nature, this could quick become an unacceptable large number.

### Stateful vs stateless
The original [zpool_spinupd](https://github.com/geppi/zpool_spinup) OpenSolaris/Illumous implementation was a stateless _Dtrace_ program that used the process name in the context of the _FBT_ provider to identify self-inflicted disk resume events. Since this information is not available in the context of the _eBPF_ kernel probe under Linux, the service has to do some bookkeeping to avoid the unnecessary proliferation of _os.open_ calls. Unfortunately _bpftrace_ does not provide the functionality required to implement a stateful service and therefore the implementation was based on _BCC_, the [BPF Compiler Collection](https://github.com/iovisor/bcc), which allows to implement communication in both directions between the _eBPF_ program in the kernel and the userland Python process of the service.

The central bookkeeping mechanism to keep state is a _BPF_HASH_ map. This map can be read and written from both sides, the _eBPF_ program in the kernel and the Python process in user space. When the Python process is triggered by the _eBPF_ kernel probe, it creates an entry in the _BPF_HASH_ map for every disk device that it will resume via an _os.open_ call. The _eBPF_ program on the other side does check the map for an entry of the device that caused a resume event and only triggers the Python process if the device is not contained in the map. In case it finds the device in the map, this means that a resume event caused by the Python process was pending and therefore just deletes this entry from the map.

Another problem is caused by the fact that sometimes a zpool is not resumed completely sequential and more than one zpool disk is resumed almost in parallel. This does create multiple entries in the ring buffer which is used for reporting a disk resume event from the eBPF program to the Python process. Each of these entries invokes the callback function of the probe which needs to identify the first of this series of resume callbacks. All resume callbacks after the first can, and should, be ignored. To facilitate the identification, a timestamp is included in the event structure that is written to the ring buffer. The timestamp of the first disk resume event in a pool is stored by the Python process and compared with the time code of later resume events. If the difference is larger than 10<sup>10</sup> nano seconds (10 sec) the current event is regarded as the first disk resume event of a new zpool wakeup. The time code of this resume event then replaces the stored time code for this zpool and the other disks of the pool are resumed. Any event whose difference is smaller than 10 sec is ignored in the Python process because it originated from a disk that was resumed almost in parallel with the first one. The threshold value of 10 sec was chosen because it is large enough to safely assume that it covers all disks that were already resumed while the Python process performs its actions and small enough to exclude, and thus identify, an intermediate suspension of the zpool.

## Miscellaneous

The service executable will output the current power management state and the configuration parameters for each monitored zpool disk to _stdout_ if it is invoked with the command name '_rpmstat_' which can be achieved with a simple symbolic link. The output contains one column each for the disk name, the current power state of the disk, if runtime power management is enabled for the disk, if power management spindown is enabled for the disk and the current autosuspend delay for the disk in seconds.