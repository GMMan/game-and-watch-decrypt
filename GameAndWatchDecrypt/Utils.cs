// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Game & Watch Encryption Utility
 * Copyright (C) 2020  Yukai Li
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
using System;
using System.Collections.Generic;
using System.Text;

namespace GameAndWatchDecrypt
{
    static class Utils
    {
        public static byte[] UIntArrayToBytes(uint[] arr, bool reverse = true, bool littleEndian = false)
        {
            byte[] buf = new byte[sizeof(uint) * arr.Length];
            int bufInd = 0;

            int i = reverse ? arr.Length - 1 : 0;
            while (reverse ? i >= 0 : i < arr.Length)
            {
                byte[] uintBytes = BitConverter.GetBytes(arr[i]);
                int j = littleEndian ? 0 : uintBytes.Length - 1;
                while (littleEndian ? j < uintBytes.Length : j >= 0)
                {
                    buf[bufInd++] = uintBytes[j];
                    j += littleEndian ? 1 : -1;
                }
                i += reverse ? -1 : 1;
            }

            return buf;
        }

        // Shuffles endianess of each word
        public static void ShuffleEndianess(byte[] data)
        {
            for (int i = 0; i < (data.Length & ~(4 - 1)); i += 4)
            {
                byte tmp = data[i + 3];
                data[i + 3] = data[i];
                data[i] = tmp;
                tmp = data[i + 2];
                data[i + 2] = data[i + 1];
                data[i + 1] = tmp;
            }
        }
    }
}
