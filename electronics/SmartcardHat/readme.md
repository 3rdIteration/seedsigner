# Smartcard Hat
This hat gives you a CCID/PCSC Compatible Smart Card interface that can connect over UART through a standard Raspberry Pi GPIO header. (Uses the SEC1210UR2 or SEC1210 URT serial interface) and also gives you a USB-C socket that you can use to power your device.

Available in three variants, one for full sized cards and one for sim sized cards and one that has slots for both. (Though you can only use one slot at a time)

Can be used for SeedSigner + Satochip functionality with this fork of SeedSigner here: https://github.com/3rdIteration/seedsigner

Will also work with all normal smartcard functions via the standard Linux CCID driver (https://github.com/LudovicRousseau/CCID) for versions above 1.6.2. (See my Github for an example configuration file)

If using a general Linux operating system with this hat, you will need to make sure that other services aren't using the UART port. (You may need to add things in your config.txt like enable_uart=1 and dtoverlay=disable-bt)

You can use either retail SeedKeeper cards or flash the applets on to a compatible Javacard.

[You can order the hat fabricated via PCBWay here](https://www.pcbway.com/project/shareproject/Smartcard_Hat_for_Raspberry_Pi_with_USB_C_Input_power_Full_SIM_Interface_57b8159c.html)

[You can also order the hat ready-made here](https://cryptoguide.tips/shop/)

# Design Notes

The following folder contains all of the design documents for the smartcard hat. The project was created in KiCAD 9 and the zip file in this folder contains the archived project. The folder also contains everything you need to have the board fabricated with JLCPCB/PCBWay, etc...

In general, the PCB has been designed quite generous tolerances that should make it easy and cheap to have fabricated just about anywhere.
* Min track width 0.2mm
* Min track space 0.15mm
* Min hole size 0.3mm
* Small, double sided board

[Manual Assembly Video](https://youtube.com/live/fEvn3GvLtko?feature=share)

# PCB Fabrication Notes
If you intend to use the PCB with a GPIO Stacking header (Adafruit 4079), the PCB thickness doesn't really matter and a 1.6mm PCB is fine. If you intend to solder the board in between the Raspberry Pi and the display hat, you will want a 1mm PCB.

# Assembly and Component Notes
## USB-C Power Input
The design includes optional USB-C input power. This can be excluded entirely if you want a simplified and slightly cheaper board, though the full-sized reader will obscure the MicroUSB ports unless used with a stacking header.

Given that USB-C chargers may deliver up to 5.5v, while the Raspberry Pi only safely supports 5.25v, the curcit includes an eFuse that will shut off the if the input voltage exceeds 5.3v. Likewise, if if the hat draws more than 2.35A the power will be shut off.

If you aren't worred about the eFuse and want simpler assembly, you can also bypass it by populating R37 with either a 0 ohm resistor or a polyfuse for whatever current you want to allow. Note that the TVS diode has been selected assuming the prsence of the eFuse, which can safely handle up to 20v on the input before clamping (Which is possible with USB-C PD in fault conditions) so you will probably want to swap the TVS for something that clamps at closer to 5.3v.

## Card Reader Socket
This hat has been designed for maximum flexibility so that the same design files can be used for full sized (Credit card sized), SIM sized or dual-slot readers with the only difference being which reader socket you connect. It's important to note that the design only uses a single Smart Card reader channel shared by all reader sockets, so you can only have one Smartcard present at a time. (And it won't work if you insert two cards at one time)

For SIM sized reader, you can simply cut the PCB along the marked line. (Tin snips work well) I have also noticed that some SIM sockets seem to be less reliable and/or more fragile (or prone to heat damage) than the full sized counterparts.

For a dual slot reader you will generally need to use it with a stacking header unless you use taller pins on your Raspberry Pi pinheader.

## Smart Card Controller
The design uses the SEC1210-URT, but if that chip is not available, you can also use the SEC1210-UR2 as a drop-in replacement. (Though it is a bit more expensive) As of the time of writing, both are readily available directly through MicroChipDirect and the SEC1210-UR2 is available through distributors like Digikey.

## Current Limit Resistors
There are two resistors, R36 and R39, which together, set the current limit for the efuse. You can use whatever value you like, as long as it sums to 25k ohm to give you the maximum current the eFuse allows. (If you want a lower current limit, you can use a higher value)

# Changelog

**v1.0.1 and 1.0.2 (Beta)**

* Improve form-factor…
* Hand assembled with low temperature solder, so may not last as long as the final fabricated boards.
* Power input protection is limited to ESD protection and overcurrent. No overvoltage protection. (Which Raspberry Pi Zero doesn’t have anyway…)

**v1.0.3 (Beta)**

* Added power LED and eFuse to provide overvoltage, undervoltage and overcurrent protection (1.8A). Overvoltage shutdown at 5.3v. (If this trips then your power supply is out of spec and could damage your Raspberry Pi)
* efuse circuit has some resistors hand soldered in…

**v1.04 (Beta)**

* Smartcard reader slot moved by 1.5mm to pass pre-fab checks at JLCPCB for a cheaper slot reader.  (But PCB same overall size as slot goes all the way to the PCB edge now)
* efuse circuit has some resistors hand soldered in…

**v1.05**

* Finalised efuse circuit (Cut-off at 5.27v)
* Added added option for SIM sized smartcard reader on the underside of the board. (Both connected to SC1, so only one slot can be used at a time)
* Populated C4, C8 and VPP pins on full sized smartcard reader. (These aren’t required for cards/applications that I have tested, but may be use by older or more specialized cards for other use cases)

**V1.0.6**

* Increase current limit to 2.35A
* Swap TVS diode for something that clamps at a higher voltage (So that even accidental 12v on input won’t harm anything, previous TVS would fry above about 6V)
* Re-organise power layout a bit with larger tracks
* Improve silkscreen annotations a bit

**V1.0.7**

* Improve copper balance to decrease PCB slight warping on some boards.

**V1.0.8**
* A couple more DFM tweaks
