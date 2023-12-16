using NetTools;

using System.Diagnostics;

namespace ARP_Scanner;

internal static class ExtentionMethods
{
    public static long Count(this IPAddressRange ipAddresses)
    {
        byte[] byteBegin = ipAddresses.Begin.GetAddressBytes();
        byte[] byteEnd = ipAddresses.End.GetAddressBytes();

        long sum = 1;
        for (int i = byteBegin.Length - 1; i >= 0; i--)
        {
            if (byteEnd[i] - byteBegin[i] == 0)
            {
                continue;
            }

            sum += (long)((byteEnd[i] - byteBegin[i]) * Math.Pow(2D, (double)(byteBegin.Length - 1 - i) * 8));
            Debug.WriteLine(sum);
        }

        return sum;
    }

    public static T[,] To2D<T>(this T[][] source)
    {
        try
        {
            int FirstDim = source.Length;
            int SecondDim = source.GroupBy(row => row.Length).Single().Key; // throws InvalidOperationException if source is not rectangular

            T[,]? result = new T[FirstDim, SecondDim];
            for (int i = 0; i < FirstDim; ++i)
            {
                for (int j = 0; j < SecondDim; ++j)
                {
                    result[i, j] = source[i][j];
                }
            }

            return result;
        }
        catch (InvalidOperationException)
        {
            throw new InvalidOperationException("The given jagged array is not rectangular.");
        }
    }
}