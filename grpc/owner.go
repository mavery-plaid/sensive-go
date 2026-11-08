// Copyright 2026 Sensive, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensivegrpc

import (
	sensiveclient "github.com/sensive-ai/sensive-go/client"
	accessv1 "github.com/sensive-ai/sensive-go/client/gen/dynax/access/v1"
)

// OwnerID is the owner of the data a request touches, by the backend's own
// identifier: the preferred form, for an owner lookup to return. It is
// sensiveclient.OwnerID.
func OwnerID(id string) *accessv1.Owner { return sensiveclient.OwnerID(id) }

// OwnerEmail is the owner of the data a request touches, by email. It is
// sensiveclient.OwnerEmail.
func OwnerEmail(email string) *accessv1.Owner { return sensiveclient.OwnerEmail(email) }
