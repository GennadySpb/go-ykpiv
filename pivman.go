// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2017
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package ykpiv

/*
#include <ykpiv.h>
#include <stdlib.h>
*/
import "C"

import (
	"crypto"
	"encoding/asn1"
	"golang.org/x/crypto/pbkdf2"

	"github.com/t33m/go-ykpiv/internal/bytearray"
)

var (
	pivmanObjData = 0x5FFF00
	pivmanProtectedData = 0x5FC109

	/* pivman's source defines this as 0x80, but since we're using an actual
	 * der decoder, we'll see the tag value, which would just be 1 */
	pivmanTagFlags1    = 0x01
	pivmanTagSalt      = 0x02
	pivmanTagTimestamp = 0x03

	pivmanTagFlags1PUKBlocked = 0x01
)

// Get the salt off the Yubikey PIV token, which is stored in a DER encoded
// array of arrays. This salt is a couple of bytes of calming entropy.
func (y Yubikey) GetSalt() ([]byte, error) {
	attributes, err := y.getPIVMANAttributes(pivmanObjData)
	if err != nil {
		return nil, err
	}
	return attributes[pivmanTagSalt], nil
}

func (y Yubikey) SetSalt(salt []byte) (err error) {
	attributes, err := y.getPIVMANAttributes(pivmanObjData)
	if err != nil {
		// TODO: handle APDUError if PIVMANAttributes is not yet set
		attributes = map[int][]byte{}
	}
	attributes[pivmanTagSalt] = salt

	values := make([]asn1.RawValue, len(attributes))
	values = append(values, asn1.RawValue{Tag: pivmanTagSalt, IsCompound: false, Class: 0x01, Bytes: salt})
	if _, ok := attributes[pivmanTagFlags1]; !ok {
		values = append(values, asn1.RawValue{Tag: pivmanTagFlags1, IsCompound: false, Class: 0x01, Bytes: []byte{0}})
	}
	if _, ok := attributes[pivmanTagTimestamp]; !ok {
		values = append(values,
			asn1.RawValue{Tag: pivmanTagTimestamp, IsCompound: false, Class: 0x01, Bytes: []byte{0, 0, 0, 0}},
		)
	}

	byteArray, err := bytearray.Encode(values)
	if err != nil {
		return
	}
	if byteArray, err = bytearray.Encode(
		[]asn1.RawValue{{Tag: 0x80, IsCompound: true, Class: 0x01, Bytes: byteArray}},
	); err != nil {
		return
	}
	return y.SaveObject(int32(pivmanObjData), byteArray)
}

// Compute the PIVMAN Management Key using 10000 rounds of PBKDF2 SHA1
// utilizing the salt off the Yubikey to derive the 3DES management key.
func (y Yubikey) DeriveManagementKey() ([]byte, error) {
	// Description of the Management key derivation can be found on the
	// Yubikey website:
	// https://developers.yubico.com/yubikey-piv-manager/PIN_and_Management_Key.html
	//
	// Technical description of Key derivation from PIN
	//
	// When choosing to use a Management Key derived from the PIN, the following takes place:
	//
	// A random 8-byte SALT value is generated and stored on the YubiKey.
	//
	// The derived Management Key is calculated as PBKDF2(PIN, SALT, 24, 10000).
	//
	// The PBKDF2 function (described in RFC 2898) is run using the PIN
	// (encoded using UTF-8) as the password, for 10000 rounds, to produce a 24
	// byte key, which is used as the management key. Whenever the user changes
	// the PIN this process is repeated, using a new SALT and the new PIN.
	pin, err := y.Options.GetPIN()
	if err != nil {
		return nil, err
	}
	salt, err := y.GetSalt()
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key([]byte(pin), salt, 10000, 24, crypto.SHA1.New), nil
}

func (y Yubikey) SetProtectedMGMKey(key []byte) (err error) {
	if err = y.SetMGMKey(key); err != nil {
		return
	}
	byteArray, err := bytearray.Encode(
		[]asn1.RawValue{asn1.RawValue{Tag: pivmanTagFlags1, IsCompound: false, Class: 0x02, Bytes: []byte{2}}},
	)
	if err != nil {
		return
	}
	if byteArray, err = bytearray.Encode(
		[]asn1.RawValue{{Tag: 0x00, IsCompound: false, Class: 0x02, Bytes: byteArray}},
	); err != nil {
		return
	}
	if err = y.SaveObject(int32(pivmanObjData), byteArray); err != nil {
		return
	}
	byteArray, err = bytearray.Encode([]asn1.RawValue{{Tag: 0x09, IsCompound: false, Class: 0x02, Bytes: key}})
	if err != nil {
		return
	}
	if byteArray, err = bytearray.Encode(
		[]asn1.RawValue{{Tag: 0x08, IsCompound: false, Class: 0x02, Bytes: byteArray}},
	); err != nil {
		return
	}
	return y.SaveObject(int32(pivmanProtectedData), byteArray)
}

func (y Yubikey) GetProtectedMGMKey() ([]byte, error) {
	attributes, err := y.getPIVMANAttributes(pivmanObjData)
	if err != nil {
		return nil, err
	}
	attributes, err = y.getPIVMANAttributes(pivmanProtectedData)
	if err != nil {
		return nil, err
	}
	return attributes[0x09], nil
}

// Return a mapping of pivmanTags -> byte arrays. The exact semantics
// of this byte array is defined entirely by the tag, and should be treated
// as semantically opaque to the user, unless specific parsing code is in place.
func (y Yubikey) getPIVMANAttributes(id int) (map[int][]byte, error) {
	attributes := map[int][]byte{}

	bytes, err := y.GetObject(id)
	if err != nil {
		return nil, err
	}

	byteArray, err := bytearray.DERDecode(bytes)
	if err != nil {
		return nil, err
	}

	for _, rawValue := range byteArray {
		attributes[rawValue.Tag] = rawValue.Bytes
	}

	return attributes, nil
}

// vim: foldmethod=marker
