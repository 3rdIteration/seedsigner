# Battery calibration (UPS HAT)

## Hardware

SeedSigner works out of the box with the [Waveshare UPS HAT (C)](https://www.waveshare.com/ups-hat-c.htm). The stock 1000mAh battery provides about 4 hours of runtime.

The battery meter will also work with any hardware that uses an INA219 battery meter connected over I2C at address `0x43`.

## Battery curves and calibration

Calibration runs the discharge test from **Tools → Battery Calibration**, logging a voltage sample every minute while the device discharges. That log is converted into a voltage-to-percent curve in 5% steps and written to the microSD card as `custom_battery_discharge_curve.json` (in the MicroSD directory).

By default, the battery meter assumes a standard 3.7V LiPo cell.

On boot, SeedSigner loads the custom curve when it exists; otherwise it falls back to the built-in default curve.
