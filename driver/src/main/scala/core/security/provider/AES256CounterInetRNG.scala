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

import org.uncommons.maths.random.{ AESCounterRNG }
import SeedSize.Seed256

/**
 * INTERNAL API
 * This class is a wrapper around the 256-bit AESCounterRNG algorithm provided by http://maths.uncommons.org/
 * It uses the default seed generator which uses one of the following 3 random seed sources:
 * Depending on availability: random.org, /dev/random, and SecureRandom (provided by Java)
 * The only method used by netty ssl is engineNextBytes(bytes)
 */
class AES256CounterInetRNG extends java.security.SecureRandomSpi {
  private val rng = new AESCounterRNG(engineGenerateSeed(Seed256))

  /**
   * This is managed internally by AESCounterRNG
   */
  override protected def engineSetSeed(seed: Array[Byte]): Unit = ()

  /**
   * Generates a user-specified number of random bytes.
   *
   * @param bytes the array to be filled in with random bytes.
   */
  override protected def engineNextBytes(bytes: Array[Byte]): Unit = rng.nextBytes(bytes)

  /**
   * Unused method
   * Returns the given number of seed bytes.  This call may be used to
   * seed other random number generators.
   *
   * @param numBytes the number of seed bytes to generate.
   * @return the seed bytes.
   */
  override protected def engineGenerateSeed(numBytes: Int): Array[Byte] = InternetSeedGenerator.getInstance.generateSeed(numBytes)
}

