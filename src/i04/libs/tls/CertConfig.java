// This file is part of the i04.libs project by MuaazH
// Copyright (C) MuaazH - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential
// Written by MuaazH <muaaz.h.is@gmail.com>
package i04.libs.tls;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author MuaazH (muaaz.h.is@gmail.com)
 */
public class CertConfig {
    public PublicKey certKey;
    public String subjectAltName;
    public CertName name;
    public CertName issuer;
    public int daysLeft;
    public boolean isCA;
    public PrivateKey signKey;
    public KeyUsage keyUsage;
    public ExtendedKeyUsage extendedKeyUsage;

    public boolean _selfSigned;
    public String _crtOutput;
    public String _keyOutput;
    public String _crtChain;
}
