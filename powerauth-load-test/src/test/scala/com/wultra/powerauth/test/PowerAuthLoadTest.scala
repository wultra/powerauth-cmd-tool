/*
 * Wultra Antivirus Server and Related Components
 * Copyright (c) 2021, Wultra s.r.o. (www.wultra.com).
 *
 * All rights reserved. This source code can be used only for purposes specified
 * by the given license contract signed by the rightful deputy of Wultra s.r.o.
 * This source code can be used only by the owner of the license.
 *
 * Any disputes arising in respect of this agreement (license) shall be brought
 * before the Municipal Court of Prague.
 */
package com.wultra.powerauth.test

import com.google.common.io.BaseEncoding
import io.gatling.core.Predef._
import io.gatling.core.structure.ScenarioBuilder
import io.gatling.http.Predef._
import io.gatling.http.protocol.HttpProtocolBuilder
import io.getlime.security.powerauth.crypto.client.activation.PowerAuthClientActivation
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
import io.getlime.security.powerauth.http.{PowerAuthEncryptionHttpHeader, PowerAuthSignatureHttpHeader}
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger
import io.getlime.security.powerauth.lib.cmd.steps.VerifySignatureStep
import io.getlime.security.powerauth.lib.cmd.steps.model.{CreateTokenStepModel, PrepareActivationStepModel}
import io.getlime.security.powerauth.lib.cmd.steps.pojo.{ActivationContext, ResultStatusObject, TokenContext, VerifySignatureContext}
import io.getlime.security.powerauth.lib.cmd.steps.v3.{CreateTokenStep, PrepareActivationStep}
import io.getlime.security.powerauth.lib.cmd.util.{ConfigurationUtil, CounterUtil, RestClientConfiguration}
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.simple.{JSONObject, JSONValue}
import org.springframework.http.HttpHeaders

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.security.interfaces.ECPublicKey
import java.security.{KeyPair, Security}
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import scala.collection.mutable.ListBuffer
// necessary `import scala.concurrent.duration._` for compilation of duration definitions
import scala.concurrent.duration._

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
class PowerAuthLoadTest extends Simulation {

  class Device {

    var activationCode: String = _
    var activationId: String = _
    var activationSignature: String = _
    var deviceKeyPair: KeyPair = _
    var password: String = _
    var resultStatusObject: ResultStatusObject = _
    var userId: String = _

    def copy(): Device = {
      val device = new Device()
      device.activationCode = this.activationCode
      device.activationId = this.activationId
      device.activationSignature = this.activationSignature
      device.deviceKeyPair = this.deviceKeyPair
      device.password = this.password
      device.resultStatusObject = this.resultStatusObject
      device.userId = this.userId

      device
    }
  }

  class ActivationCreateCall(
                              val httpEncryptionHeader: String,
                              val encryptedRequestL1: EciesEncryptedRequest,
                              val stepContext: ActivationContext
                            )

  class TokenCreateCall(
                         val header: String,
                         val request: EciesEncryptedRequest,
                         val stepContext: TokenContext
                       )

  class SignatureVerifyCall(
                             val header: String,
                             val request: Array[Byte],
                             val stepContext: VerifySignatureContext
                           )

  // Add Bouncy Castle Security Provider
  Security.addProvider(new BouncyCastleProvider)

  val POWERAUTH_SERVER_URL: String = System.getProperty("powerAuthServerUrl", "http://localhost:8080")

  val POWERAUTH_REST_SERVER_URL: String = System.getProperty("powerAuthRestServerUrl", "http://localhost:8081")

  val httpProtocolPowerAuthServer: HttpProtocolBuilder = http
    .baseUrl(POWERAUTH_SERVER_URL)
    .inferHtmlResources()
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("PowerAuthLoadTest/gatling (macOS; cs-CZ; Wifi) com.wultra.powerauth/0.0.1-SNAPSHOT")

  val httpProtocolPowerAuthRestServer: HttpProtocolBuilder = http
    .baseUrl(POWERAUTH_REST_SERVER_URL)
    .inferHtmlResources()
    .acceptHeader("application/json")
    .contentTypeHeader("application/json")
    .userAgentHeader("PowerAuthLoadTest/gatling (macOS; cs-CZ; Wifi) com.wultra.powerauth/0.0.1-SNAPSHOT")

  val activationPrepareStep = new PrepareActivationStep
  val signatureVerifyStep = new VerifySignatureStep
  val tokenCreateStep = new CreateTokenStep

  private val activation = new PowerAuthClientActivation
  private val eciesFactory = new EciesFactory
  private val mapper = RestClientConfiguration.defaultMapper

  // disable/enable step logger
  val stepLogger: JsonStepLogger = null // new JsonStepLogger(System.out)

  val clientConfigObject: JSONObject = {
    try {
      val configFileBytes: Array[Byte] = Files.readAllBytes(Paths.get(System.getProperty("configFile", "./config.json")))
      JSONValue.parse(new String(configFileBytes, StandardCharsets.UTF_8)).asInstanceOf[JSONObject]
    } catch {
      case e: Throwable =>
        if (stepLogger != null) {
          stepLogger.writeItem("generic-error-config-file-invalid", "Invalid config file", "Config file must be in a correct JSON format?", "ERROR", e)
        }
        throw e
    }
  }

  val activationName: String = ConfigurationUtil.getApplicationName(clientConfigObject)
  val applicationId: Long = clientConfigObject.get("applicationId").asInstanceOf[Long]
  val applicationKey: String = ConfigurationUtil.getApplicationKey(clientConfigObject)
  val applicationSecret: String = ConfigurationUtil.getApplicationSecret(clientConfigObject)
  val masterPublicKey: ECPublicKey = ConfigurationUtil.getMasterKey(clientConfigObject, stepLogger).asInstanceOf[ECPublicKey]
  val modelVersion: String = "3.1"

  val NUMBER_OF_DEVICES: Integer = Integer.getInteger("numberOfDevices", 1)

  println(s"Load testing PowerAuth")

  val devicesToInit: Array[Device] = (1 to NUMBER_OF_DEVICES).toList
    .map(index => {
      val device = new Device()
      device.userId = s"loadTestUser_$index"
      device
    }).toArray

  val devicesActivated: ListBuffer[Device] = ListBuffer.empty[Device]
  val devicesInitialized: ListBuffer[Device] = ListBuffer.empty[Device]
  val indexInitialized: AtomicInteger = new AtomicInteger(0)
  val indexTokenCreate: AtomicInteger = new AtomicInteger(0)
  val indexSignatureVerify: AtomicInteger = new AtomicInteger(0)

  val scnActivationInit: ScenarioBuilder = scenario("scnActivationInit")
    .feed(devicesToInit.map(device => Map("device" -> device, "userId" -> device.userId)).circular)
    .exec(http("PowerAuth - activation init")
      .post("/rest/v3/activation/init")
      .body(StringBody(session => {
        s"""{
			    "requestObject": {
					  "activationOtpValidation": "NONE",
						"applicationId": "$applicationId",
						"userId": "${session("userId").as[String]}"
					}
				}"""
      }
      ))
      .check(jsonPath("$.status").is("OK"))
      .check(jsonPath("$.responseObject.activationCode").saveAs("activationCode"))
      .check(jsonPath("$.responseObject.activationId").saveAs("activationId"))
      .check(jsonPath("$.responseObject.activationSignature").saveAs("activationSignature"))
    )
    .exec(session => {
      val deviceToInit = session("device").as[Device]

      val deviceKeyPair = activation.generateDeviceKeyPair

      val device: Device = deviceToInit.copy()
      device.activationCode = session("activationCode").as[String]
      device.activationId = session("activationId").as[String]
      device.activationSignature = session("activationSignature").as[String]
      device.deviceKeyPair = deviceKeyPair
      device.password = s"Password_${deviceToInit.userId}"
      device.resultStatusObject = new ResultStatusObject()

      synchronized {
        devicesInitialized += device
      }
      session
    })

  val scnActivationCreate: ScenarioBuilder = scenario("scnActivationCreate")
    .exec(session => {
      val device = nextDevice(devicesInitialized, indexInitialized)
      val data = prepareActivationCall(device)
      session
        .set("device", device)
        .set("encryptedRequestL1", data.encryptedRequestL1)
        .set("httpEncryptionHeader", data.httpEncryptionHeader)
        .set("stepContext", data.stepContext)
    })
    .exec(http("PowerAuth - activation create")
      .post("/pa/v3/activation/create")
      .header(PowerAuthEncryptionHttpHeader.HEADER_NAME, "${httpEncryptionHeader}")
      .body(StringBody(session => {
        val objectRequest = session("encryptedRequestL1").as[EciesEncryptedRequest]
        mapper.writeValueAsString(objectRequest)
      }))
      .check(jsonPath("$.encryptedData").saveAs("encryptedData"))
      .check(jsonPath("$.mac").saveAs("mac"))
    )
    .exec(session => {
      val device: Device = session("device").as[Device]

      val response = new EciesEncryptedResponse(session("encryptedData").as[String], session("mac").as[String])
      val stepContext = session("stepContext").as[ActivationContext]
      val resultStatusObject = activationPrepareStep.processResponse(response, stepContext)

      val deviceActivated: Device = device.copy()
      deviceActivated.resultStatusObject = resultStatusObject

      synchronized {
        // TODO remove device from devicesInitialized
        devicesActivated += deviceActivated
      }
      session
    })

  val scnTokenCreate: ScenarioBuilder = scenario("scnTokenCreate")
    .exec(session => {
      val device = nextDevice(devicesActivated, indexTokenCreate)
      val data = device.synchronized {
        prepareTokenCreateCall(device)
      }
      session
        .set("device", device)
        .set("httpAuthorizationHeader", data.header)
        .set("request", data.request)
        .set("stepContext", data.stepContext)
    })
    .exec(http("PowerAuth - token create")
      .post("/pa/v3/token/create")
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpAuthorizationHeader}")
      .body(ByteArrayBody(session => {
        RestClientConfiguration.defaultMapper.writeValueAsBytes(session("request").as[EciesEncryptedRequest])
      }))
      .check(jsonPath("$.encryptedData").saveAs("encryptedData"))
      .check(jsonPath("$.mac").saveAs("mac"))
    )
    .exec(session => {
      val response = new EciesEncryptedResponse(session("encryptedData").as[String], session("mac").as[String])
      val stepContext = session("stepContext").as[TokenContext]

      tokenCreateStep.processResponse(response, new HttpHeaders(), stepContext)

      session
    })

  val scnSignatureVerify: ScenarioBuilder = scenario("scnSignatureVerify")
    .exec(session => {
      val device = nextDevice(devicesActivated, indexSignatureVerify)
      val data = device.synchronized {
        prepareSignatureVerifyCall(device)
      }
      session
        .set("device", device)
        .set("httpAuthorizationHeader", data.header)
        .set("request", data.request)
        .set("stepContext", data.stepContext)
    })
    .exec(http("PowerAuth - signature verify")
      .post("/pa/v3/signature/validate")
      .header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpAuthorizationHeader}")
      .body(ByteArrayBody(session => {
        session("request").as[Array[Byte]]
      }))
      .check(jsonPath("$.status").is("OK"))
    )
    .exec(session => {
      session
    })

  setUp(
    scnActivationInit.inject(
      rampUsers(NUMBER_OF_DEVICES).during((NUMBER_OF_DEVICES.floatValue() / 200).intValue().seconds)
    ).protocols(httpProtocolPowerAuthServer)
      .andThen(
        scnActivationCreate.inject(
          rampUsers(NUMBER_OF_DEVICES).during((NUMBER_OF_DEVICES.floatValue() / 100).intValue().seconds)
        ).protocols(httpProtocolPowerAuthRestServer)
          .andThen(
            scnTokenCreate.inject(
              rampUsersPerSec(1).to(30).during(10.minutes)
            ).protocols(httpProtocolPowerAuthRestServer),
            scnSignatureVerify.inject(
              rampUsersPerSec(1).to(30).during(10.minutes)
            ).protocols(httpProtocolPowerAuthRestServer)
          )
      )
  )

  def prepareActivationCall(device: Device): ActivationCreateCall = {
    val model: PrepareActivationStepModel = new PrepareActivationStepModel()
    model.setActivationCode(device.activationCode)
    model.setActivationName(activationName)
    model.setApplicationKey(applicationKey)
    model.setApplicationSecret(applicationSecret)
    model.setDeviceInfo(s"Device Info ${device.userId}")
    model.setMasterPublicKey(masterPublicKey)
    model.setPassword(device.password)
    model.setPlatform("devicePlatform")
    model.setVersion(modelVersion)

    val applicationSecretBytes = applicationSecret.getBytes(StandardCharsets.UTF_8)

    val eciesEncryptorL1 = eciesFactory.getEciesEncryptorForApplication(masterPublicKey, applicationSecretBytes, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC)
    val eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication(masterPublicKey, applicationSecretBytes, EciesSharedInfo1.ACTIVATION_LAYER_2)

    val stepContext = ActivationContext.builder
      .deviceKeyPair(device.deviceKeyPair)
      .eciesEncryptorL1(eciesEncryptorL1)
      .eciesEncryptorL2(eciesEncryptorL2)
      .modelPrepare(model)
      .password(device.password)
      .resultStatusObject(device.resultStatusObject)
      .stepLogger(stepLogger).build

    val encryptedRequestL1: EciesEncryptedRequest = activationPrepareStep.createRequest(stepContext)

    val header: PowerAuthEncryptionHttpHeader = new PowerAuthEncryptionHttpHeader(model.getApplicationKey, model.getVersion)
    val httpEncryptionHeader: String = header.buildHttpHeader

    new ActivationCreateCall(httpEncryptionHeader, encryptedRequestL1, stepContext)
  }

  def prepareTokenCreateCall(device: Device): TokenCreateCall = {
    val resultStatusObject = device.resultStatusObject

    val model = new CreateTokenStepModel
    model.setApplicationKey(applicationKey)
    model.setApplicationSecret(applicationSecret)
    model.setPassword(device.password)
    model.setResultStatusObject(resultStatusObject)
    model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
    model.setVersion(modelVersion)

    val transportMasterKeyBytes = BaseEncoding.base64.decode(resultStatusObject.getTransportMasterKey)
    val serverPublicKey = resultStatusObject.getServerPublicKeyObject.asInstanceOf[ECPublicKey]
    val encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret.getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes, EciesSharedInfo1.CREATE_TOKEN)

    val stepContext = TokenContext.builder
      .encryptor(encryptor)
      .model(model)
      .password(device.password)
      .resultStatusObject(resultStatusObject)
      .stepLogger(stepLogger)
      .build

    val request = tokenCreateStep.createRequest(stepContext)

    val signatureHeader = tokenCreateStep.createSignatureHeader(request, stepContext)
    val httpAuthorizationHeader = signatureHeader.buildHttpHeader

    CounterUtil.incrementCounter(model)

    new TokenCreateCall(httpAuthorizationHeader, request, stepContext)
  }

  def prepareSignatureVerifyCall(device: Device): SignatureVerifyCall = {
    val resultStatusObject = device.resultStatusObject

    import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
    import io.getlime.security.powerauth.lib.cmd.steps.model.VerifySignatureStepModel
    import io.getlime.security.powerauth.lib.cmd.util.ConfigurationUtil

    val model = new VerifySignatureStepModel
    model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject))
    model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject))
    model.setHeaders(Collections.emptyMap())
    model.setHttpMethod("POST")
    model.setPassword(device.password)
    model.setResourceId("/pa/signature/validate")
    model.setResultStatusObject(resultStatusObject)
    model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
    model.setUriString(s"$POWERAUTH_REST_SERVER_URL/pa/v3/signature/validate")
    model.setVersion(modelVersion)
    model.setDryRun(false)

    val dataFileBytes = "TEST_DATA".getBytes(StandardCharsets.UTF_8)
    model.setData(dataFileBytes)

    val stepContext = VerifySignatureContext.builder
      .model(model)
      .resultStatusObject(resultStatusObject)
      .stepLogger(stepLogger)
      .build()

    val signatureHeader = signatureVerifyStep.createSignature(stepContext, dataFileBytes)
    val httpAuthorizationHeader = signatureHeader.buildHttpHeader

    CounterUtil.incrementCounter(model)

    new SignatureVerifyCall(httpAuthorizationHeader, dataFileBytes, stepContext)
  }

  def nextDevice(devices: ListBuffer[Device], indexCounter: AtomicInteger): Device = {
    var index = indexCounter.incrementAndGet()
    if (index >= devices.size) {
      indexCounter.set(0)
      index = 0
    }
    devices(index)
  }

}
