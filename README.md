# Let-Me-In
- A kernel-based injector for TLG.



# Build

- CMake 3.27+
- Visual Studio 2019+ build tools
- Windows Driver Kit 10



```
1. Build TLG-Loader-Driver with Visual Studio 2019+.
2. Build tlg_driver with CMAKE using Visual Studio tool chain and Visual Studio generator. The driver compiled in the first step will automatically included in the program.

Run tlg_starter.exe. It will inject loader.dll into the game.
```



# Credits

### Library

- [libKDU](https://github.com/dumbasPL/libKDU)



### Inspiration

- [KDU](https://github.com/hfiref0x/KDU)

- [驱动开发：内核远程线程实现DLL注入](https://www.cnblogs.com/LyShark/p/17172407.html)

- [Windows 11 SSDT & ShadowSSDT Address Acquisition Problem](https://debugwar.com/article/Windows-11-SSDT-and-ShadowSSDT-fetch-problem)
