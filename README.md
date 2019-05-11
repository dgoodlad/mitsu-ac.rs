# mitsu_ac

Reverse-engineered protocol implementation in Rust for some Mitsubishi heat
pumps (aka air conditioners) with CN105 connectors. Based heavily on the work in
[SwiCago/HeatPump](https://github.com/SwiCago/HeatPump).

**This library is in its very early stages, and is quite untested.**

It is intended for use on embedded hardware, and as such is `no_std`.

There is no code to actually interface with a serial device here. The CN105
serial connection operates at 2400 baud, 8 bits per byte, even parity with 1
stop bit (2400 8E1). You should configure your serial peripheral as such,
and use this library to parse/encode data on that line.

For more usage, see the docs.
