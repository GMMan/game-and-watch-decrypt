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
    class KeyInfoParsed
    {
        public uint FileBase { get; set; }

        public byte[] OtfDecKey { get; set; }
        public byte[] OtfDecIv { get; set; }
        public uint OtfDecStart { get; set; }
        public uint OtfDecEnd { get; set; }

        public byte[] AesGcmKey { get; set; }
        public byte[] AesGcmIv { get; set; }
        public uint AesGcmBase { get; set; }
        //public int AesGcmCopyNum { get; set; }
        public uint AesGcmRegionLength { get; set; }
        public uint AesGcmDataLength { get; set; }

        public bool IsOtfDecPresent => OtfDecKey != null;
        public bool IsAesGcmPresent => AesGcmKey != null;
    }
}
