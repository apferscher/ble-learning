# Fingerprinting Bluetooth Low Energy via Active Automata Learning


This repository contains the supplemental material to the paper 'Fingerprinting Bluetooth Low Energy via Active Automata Learning' of Andrea Pferscher and Bernhard K. Aichernig (Institute of Software Technology, Graz University of Technology).

##  Content
 - Learned models ([learned-automata/](https://github.com/apferscher/ble-learning/tree/main/learned-automata)):
    - [CYBLE-416045-02](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CYBLE-416045-02.dot)
    - [nRF52832](https://github.com/apferscher/ble-learning/blob/main/learned-automata/nRF52832.dot) 
    - [CC2650](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CC2650.dot)
    - [CYW43455](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CYW43455.dot)
    - [CC2640R2 (no pairing request)](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CC2640R2-no-pairing-req.dot)
    - [CC2640R2 (no length request)](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CC2640R2-no-length-req.dot)
    - [CC2640R2 (no feature request)](https://github.com/apferscher/ble-learning/blob/main/learned-automata/CC2640R2-no-feature-req.dot)
- Learning results ([learning-results/](https://github.com/apferscher/ble-learning/tree/main/learning-results)):
    - [CYBLE-416045-02](https://github.com/apferscher/ble-learning/blob/main/learning-results/CYBLE-416045-02.txt)
    - [nRF52832](https://github.com/apferscher/ble-learning/blob/main/learning-results/nRF52832.txt)
    - [CC2650](https://github.com/apferscher/ble-learning/blob/main/learning-results/CC2650.txt)
    - [CYW43455](https://github.com/apferscher/ble-learning/blob/main/learning-results/CYW43455.txt)
    - [CC2640R2 (no pairing request)](https://github.com/apferscher/ble-learning/blob/main/learning-results/CC2640R2-no-pairing-req.txt)
    - [CC2640R2 (no length request)](https://github.com/apferscher/ble-learning/blob/main/learning-results/CC2640R2-no-length-req.txt)
    - [CC2640R2 (no feature request)](https://github.com/apferscher/ble-learning/blob/main/learning-results/CC2640R2-no-feature-req.txt)
- Firmware ([firmware/](https://github.com/apferscher/ble-learning/tree/main/firmware))
    - [Nordic nRF52840 Dongle](https://github.com/apferscher/ble-learning/blob/main/firmware/nRF52840_dongle_firmware.hex)
    - [Nordic nRF52840 Development Kit](https://github.com/apferscher/ble-learning/blob/main/firmware/nrf52840_dk_firmware.hex)
- Framework
    - experiment execution ([ble_learning.py](https://github.com/apferscher/ble-learning/blob/main/ble_learning.py))

## Installation

### Prerequisites

1. Nordic nRF52840 Dongle or Development Kit flashed with corresponding firmware
2. Python libraries [Scapy >=v2.4.5]() and [Aalpy >=1.0.1]()


The firmware is taken from the [SweynTooth project](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks).