# perfPI

**perfPI** is a multimodal system for detecting unexpected application network activity by comparing an application's **workload** with its **network behavior**.

The core idea is:

> Does the application's network activity make sense given the amount and type of work it is performing?

The system combines network measurements with Windows performance measurements and hardware performance counters. It uses classical probability theory and likelihood-ratio testing rather than machine learning, neural networks, or other AI methods.

## Approach

The system collects three types of information:

1. **Network activity**
   - Packet counts
   - Packet sizes
   - Timestamps
   - Inter-arrival times
   - Source and destination information
   - Ports and protocols
   - Connection information

2. **Windows Performance Counters**
   - CPU usage
   - I/O bytes
   - I/O operations
   - Page faults
   - Thread count
   - Context switches

3. **Hardware Performance Counters**
   - Total CPU cycles
   - Instructions retired
   - LLC misses
   - Instructions-per-cycle (IPC)

The workload measurements provide context for interpreting network activity.

## System Architecture

```text
                    Raspberry Pi
                         |
                     PCAP capture
                         |
                         v
                    receive.exe
                         |
                         v
                   received.pcap
                         |
                         v
                     process.exe
                         |
                         v
                       TShark
                         |
                         v
                   packet_data.csv


                    Windows Host
                         |
                         v
               capture_windows.exe
                    /          \
                   /            \
                  v              v
       Windows Performance      Hardware
          Counters              Counters
              |                    |
              v                    v
      windows_perf.csv           hpc.etl
                   \              /
                    \            /
                     v          v
                  Data preparation
                         |
                         v
                   Feature vectors
                         |
                         v
                 Probability model
                         |
                         v
                Likelihood-ratio test
                         |
                         v
               Normal / Unexpected
