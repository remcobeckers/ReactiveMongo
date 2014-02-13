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

//Copied from package akka.remote.transport.netty and modified for client SSL connections.

package reactivemongo.core.ssl

import akka.event.LoggingAdapter
import akka.japi.Util._
import com.typesafe.config.Config
import java.io.{ IOException, FileNotFoundException, FileInputStream }
import java.security._
import javax.net.ssl.{ KeyManagerFactory, TrustManager, TrustManagerFactory, SSLContext }
import org.jboss.netty.handler.ssl.SslHandler
import scala.util.Try

import reactivemongo.core.errors.GenericDriverException
import reactivemongo.core.security.provider._
import reactivemongo.utils.LazyLogger

@SerialVersionUID(1L)
class SSLConfigurationException(message: String, cause: Throwable) extends RuntimeException(message, cause) with Serializable {
  def this(msg: String) = this(msg, null)
}

@SerialVersionUID(1L)
class SSLConnectionException(message: String, cause: Throwable) extends RuntimeException(message, cause) with Serializable {
  def this(msg: String) = this(msg, null)
}

private[core] class SSLSettings(config: Config) {

  import config._

  private def emptyIsNone(s: String): Option[String] = Option(s).filter(_.length > 0)

  val SSLTrustStore: Option[TrustStoreSettings] = Option(root().get("trust-store"))
                                                    .map(_ => getConfig("trust-store"))
                                                    .map(c => TrustStoreSettings(c.getString("path"), c.getString("password")))

  val SSLEnabledAlgorithms = immutableSeq(getStringList("enabled-cipher-suites")).to[Set]

  val SSLProtocol = emptyIsNone(getString("protocol"))

  val SSLRandomNumberGenerator = emptyIsNone(getString("random-number-generator"))

  if (SSLProtocol.isEmpty) throw new SSLConfigurationException(
    "Configuration option 'mongo-async-driver.enable-ssl is turned on but no protocol is defined in 'mongo-async-driver.ssl.protocol'.")

  SSLTrustStore.foreach { ts =>
    if(ts.path.isEmpty || ts.password.isEmpty)
      throw new SSLConfigurationException("Configuration options 'mongo-async-driver.ssl.trust-store.path' and 'mongo-async-driver.ssl.trust-store.password' are required. Remove 'mongo-async-driver.ssl.trust-store' config section completely if you want the SSL context to search for installed security providers in the runtime.")
    if(ts.path.isEmpty && ts.password.isEmpty)
      throw new SSLConfigurationException("Configuration options 'mongo-async-driver.ssl.trust-store.path' and 'mongo-async-driver.ssl.trust-store.password' are both not defined. Remove 'mongo-async-driver.ssl.trust-store' config section completely if you want the SSL context to search for installed security providers in the runtime.")
  }
}

private [core] case class TrustStoreSettings(path: String, password: String)

/**
 * Used for adding SSL support to Netty pipeline
 */
private [core] object NettySSLSupport {

  /**
   * Construct a SSLHandler which can be inserted into a Netty server/client pipeline
   */
  def apply(settings: SSLSettings, log: LazyLogger): SslHandler = initializeClientSSL(settings, log)

  def initializeCustomSecureRandom(rngName: Option[String], log: LazyLogger): SecureRandom = {
    val rng = rngName match {
      case Some(r @ ("AES128CounterSecureRNG" | "AES256CounterSecureRNG" | "AES128CounterInetRNG" | "AES256CounterInetRNG")) ⇒
        log.debug(s"SSL random number generator set to: ${r}")
        SecureRandom.getInstance(r, ReactiveMongoProvider)
      case Some(s @ ("SHA1PRNG" | "NativePRNG")) ⇒
        log.debug("SSL random number generator set to: " + s)
        // SHA1PRNG needs /dev/urandom to be the source on Linux to prevent problems with /dev/random blocking
        // However, this also makes the seed source insecure as the seed is reused to avoid blocking (not a problem on FreeBSD).
        SecureRandom.getInstance(s)
      case Some(unknown) ⇒
        log.debug(s"Unknown SSLRandomNumberGenerator [${unknown}] falling back to SecureRandom")
        new SecureRandom
      case None ⇒
        log.debug("SSLRandomNumberGenerator not specified, falling back to SecureRandom")
        new SecureRandom
    }
    rng.nextInt() // prevent stall on first access
    rng
  }

  def initializeClientSSL(settings: SSLSettings, log: LazyLogger): SslHandler = {
    log.debug("Client SSL is enabled, initialising ...")

    def constructClientContext(settings: SSLSettings, log: LazyLogger, protocol: String): Option[SSLContext] =
      try {
        val rng = initializeCustomSecureRandom(settings.SSLRandomNumberGenerator, log)

        val trustManagers = settings.SSLTrustStore.map { trustStoreSettings =>
          val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
          trustManagerFactory.init({
            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
            val fin = new FileInputStream(trustStoreSettings.path)
            try trustStore.load(fin, trustStoreSettings.password.toCharArray) finally Try(fin.close())
            trustStore
          })
          trustManagerFactory.getTrustManagers
        }.getOrElse{
          log.debug("mongo-async-driver.ssl.trust-store not specified, SSL context will search installed security providers and use the first entry of the highest priority implementation.")
          null
        }

        Option(SSLContext.getInstance(protocol)) map { ctx =>
          ctx.init(null, trustManagers, rng)
          ctx
        }
      } catch {
        case e: FileNotFoundException    ⇒ throw new SSLConnectionException("Client SSL connection could not be established because trust store could not be loaded", e)
        case e: IOException              ⇒ throw new SSLConnectionException("Client SSL connection could not be established because: " + e.getMessage, e)
        case e: GeneralSecurityException ⇒ throw new SSLConnectionException("Client SSL connection could not be established because SSL context could not be constructed", e)
      }

    ((settings, settings.SSLProtocol) match {
      case (settings, Some(protocol)) ⇒ constructClientContext(settings, log, protocol)
      case (settings, protocol) ⇒ throw new GeneralSecurityException("mongo-async-driver.ssl.protocol is are missing.")
    }) match {
      case Some(context) ⇒
        log.debug("Using client SSL context to create SSLEngine ...")
        val sslHandler = new SslHandler({
          val sslEngine = context.createSSLEngine
          sslEngine.setUseClientMode(true)
          val enabledAlgorithms = settings.SSLEnabledAlgorithms.toArray
          if(!enabledAlgorithms.isEmpty) {
            sslEngine.setEnabledCipherSuites(enabledAlgorithms)
          }
          sslEngine
        })
        sslHandler.setIssueHandshake(true)
        sslHandler
      case None ⇒
        throw new GeneralSecurityException(
          """Failed to initialize client SSL because SSL context could not be found." +
              "Make sure your settings are correct: [trust-store: %s] [protocol: %s]""".format(
            settings.SSLTrustStore,
            settings.SSLProtocol))
    }
  }
}
