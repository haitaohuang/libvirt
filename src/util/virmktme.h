/*
* virmktme.h: MKTME kernel calls
*
* Copyright (C) 2016 Red Hat, Inc.
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library.  If not, see
* <http://www.gnu.org/licenses/>.
*/


#ifndef LIBVIRT_VIRMKTME_H
#define LIBVIRT_VIRMKTME_H

int
virGetMktmeKeyHandle(const char* id, const char* type,
	const char* key, const char *algorithm);

int
virMktmeIsEnabled(void);

#define LIBVIRT_MKTME_KEY_RING_NAME      "mktme_key_ring_service"
#endif
