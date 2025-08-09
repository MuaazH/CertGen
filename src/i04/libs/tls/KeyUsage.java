// This file is part of the i04.libs project by MuaazH
// Copyright (C) MuaazH - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential
// Written by MuaazH <muaaz.h.is@gmail.com>
package i04.libs.tls;

/**
 * @author MuaazH (muaaz.h.is@gmail.com)
 */
public class KeyUsage {
    public boolean digitalSignature;
    public boolean nonRepudiation;
    public boolean keyEncipherment;
    public boolean dataEncipherment;
    public boolean keyAgreement;
    public boolean keyCertSign;
    public boolean crlSign;
    public boolean encipherOnly;
    public boolean decipherOnly;
}
