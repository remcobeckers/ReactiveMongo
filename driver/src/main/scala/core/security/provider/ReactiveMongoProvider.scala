// ============================================================================
// Copyright (C) 2009-2014 Typesafe Inc. <http://www.typesafe.com>
//
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
// ============================================================================

package reactivemongo.core.security.provider

import java.security.{ PrivilegedAction, AccessController, Provider, Security }

/**
 * A provider that for AES128CounterRNGFast, a cryptographically secure random number generator through SecureRandom
 */
object ReactiveMongoProvider extends Provider("ReactiveMongo", 1.0, "ReactiveMongo provider 1.0 that implements a secure AES random number generator") {
  AccessController.doPrivileged(new PrivilegedAction[this.type] {
    def run = {
      //SecureRandom
      put("SecureRandom.AES128CounterSecureRNG", classOf[AES128CounterSecureRNG].getName)
      put("SecureRandom.AES256CounterSecureRNG", classOf[AES256CounterSecureRNG].getName)
      put("SecureRandom.AES128CounterInetRNG", classOf[AES128CounterInetRNG].getName)
      put("SecureRandom.AES256CounterInetRNG", classOf[AES256CounterInetRNG].getName)

      //Implementation type: software or hardware
      put("SecureRandom.AES128CounterSecureRNG ImplementedIn", "Software")
      put("SecureRandom.AES256CounterSecureRNG ImplementedIn", "Software")
      put("SecureRandom.AES128CounterInetRNG ImplementedIn", "Software")
      put("SecureRandom.AES256CounterInetRNG ImplementedIn", "Software")
      null //Magic null is magic
    }
  })
}
