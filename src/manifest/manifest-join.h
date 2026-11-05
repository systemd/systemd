/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "manifest-util.h"

/* Joins the specified UAPI.16 manifests into one, which is written to the output configured in the context,
 * and signed if a private key is configured there. Objects of the same name must be identical in all inputs
 * (except for their inode tokens and modification times, of which the newest wins), otherwise the join
 * fails. Hardlink groups are combined across inputs. The
 * inputs are not verified in any way: signatures are ignored and dropped, and no consistency checks beyond
 * the above are made. Use manifest_verify() for that. The output is deterministic: objects are sorted the
 * same way manifest_make() sorts them, and inode tokens are renumbered in order of appearance, whatever the
 * order of the inputs. With a single input this is hence a way to (re-)sign or unsign a manifest, and to
 * bring it into canonical form. */
int manifest_join(ManifestContext *c, char * const *inputs);
