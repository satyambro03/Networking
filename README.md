# NetScope - Network Packet Analyzer

## About
NetScope is a C-based network packet analyzer
built using the libpcap library.

## Features
- PCAP file analysis
- Ethernet frame parsing
- IPv4 address extraction
- TCP packet identification
- UDP packet identification
- ICMP packet identification
- Source and destination port extraction
- Protocol statistics
- CSV report generation

## Technology Stack
- C Programming
- Linux
- GCC
- libpcap
- GDB
- Git

## Installation

sudo apt install gcc libpcap-dev

## Compilation

gcc -Wall -Wextra src/main.c -o netscope -lpcap

## Execution

./netscope data/sample.pcap

## Developer
Solo Hackathon Project

## Track
Computer Networks



