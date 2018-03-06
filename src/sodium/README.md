# LibSodium #

This directory contains all of our code wrapping libsodium. Since libsodium is a native library
we have to use some unsafe blocks to interact with them. The goal here is to keep all the unsafe
pieces of code in one module.

You shouldn't need anything in this directory to use the library, but if you're interested in how
we're interacting with libsdoium then this is the place to be.
