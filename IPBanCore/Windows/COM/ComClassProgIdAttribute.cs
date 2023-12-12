using System;
using System.Linq;

namespace DigitalRuby.IPBanCore.Windows.COM
{
    internal class ComClassProgIdAttribute(string classProgId) : Attribute
    {
        public string ClassProgId { get; } = classProgId;

        public static string GetClassProgId<T>()
        {
            return typeof(T)
                .GetCustomAttributes(typeof(ComClassProgIdAttribute), true)
                .OfType<ComClassProgIdAttribute>()
                .FirstOrDefault()?.ClassProgId;
        }
    }
}