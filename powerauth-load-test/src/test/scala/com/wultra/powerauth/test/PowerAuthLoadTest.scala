/*
 * Wultra Antivirus Server and Related Components
 * Copyright (c) 2019, Wultra s.r.o. (www.wultra.com).
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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.{EciesEncryptor, EciesFactory}
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor
import io.getlime.security.powerauth.http.{PowerAuthEncryptionHttpHeader, PowerAuthSignatureHttpHeader}
import io.getlime.security.powerauth.lib.cmd.logging.JsonStepLogger
import io.getlime.security.powerauth.lib.cmd.steps.model.{CreateTokenStepModel, PrepareActivationStepModel}
import io.getlime.security.powerauth.lib.cmd.steps.pojo.{ActivationContext, ResultStatusObject, TokenContext}
import io.getlime.security.powerauth.lib.cmd.steps.v3.{CreateTokenStep, PrepareActivationStep}
import io.getlime.security.powerauth.lib.cmd.util.{ConfigurationUtil, RestClientConfiguration}
import io.getlime.security.powerauth.rest.api.model.entity.TokenResponsePayload
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.simple.{JSONObject, JSONValue}
import org.springframework.http.HttpHeaders

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.security.interfaces.ECPublicKey
import java.security.{KeyPair, Security}
import java.util.concurrent.atomic.AtomicInteger
import scala.collection.mutable
import scala.collection.mutable.ListBuffer
// necessary `import scala.concurrent.duration._` for compilation of duration definitions
import scala.concurrent.duration._

/**
 * @author Lukas Lukovsky, lukas.lukovsky@wultra.com
 */
class PowerAuthLoadTest extends Simulation {

	// Add Bouncy Castle Security Provider
	Security.addProvider(new BouncyCastleProvider)

	val httpProtocolPowerAuthServer: HttpProtocolBuilder = http
		.baseUrl("http://localhost:8080")
		.inferHtmlResources()
		.acceptHeader("application/json")
		.contentTypeHeader("application/json")
		.userAgentHeader("PowerAuthLoadTest/gatling (macOS; cs-CZ; Wifi) com.wultra.powerauth/0.0.1-SNAPSHOT")

	val httpProtocolPowerAuthRestServer: HttpProtocolBuilder = http
		.baseUrl("http://localhost:8081")
		.inferHtmlResources()
		.acceptHeader("application/json")
		.contentTypeHeader("application/json")
		.userAgentHeader("PowerAuthLoadTest/gatling (macOS; cs-CZ; Wifi) com.wultra.powerauth/0.0.1-SNAPSHOT")

	val signatureType: String = "possession_knowledge"

	val prepareActivationStep = new PrepareActivationStep
	val createTokenStep = new CreateTokenStep

	private val activation = new PowerAuthClientActivation
	private val eciesFactory = new EciesFactory
	private val keyConvertor = new KeyConvertor
	private val mapper = RestClientConfiguration.defaultMapper

	// disable/enable step logger
	val stepLogger: JsonStepLogger = null // new JsonStepLogger(System.out)

	val NUMBER_OF_DEVICES = 1

	val configFileBytes: Array[Byte] = Files.readAllBytes(Paths.get("/Users/lukas/projects/powerauth/test/config.json"))

	val clientConfigObject: JSONObject = {
		try {
			JSONValue.parse(new String(configFileBytes, StandardCharsets.UTF_8)).asInstanceOf[JSONObject]
		} catch {
			case e: Throwable =>
				if (stepLogger != null) {
					stepLogger.writeItem("generic-error-config-file-invalid", "Invalid config file", "Config file must be in a correct JSON format?", "ERROR", e)
				}
				throw e
		}
	}

	println(s"Load testing PowerAuth")

	val devicesSequence: Seq[Int] = (1 to NUMBER_OF_DEVICES).toList
	val devicesToInit: Array[mutable.Map[String, Any]] = devicesSequence
		.map(index =>
			mutable.Map(
				"index" -> index,
				"userId" -> s"loadTestUser_$index"
			)
		).toArray

	val userIds: Array[String] = devicesToInit.map(device => device("userId").asInstanceOf[String])
	val devicesByUserIdMap: mutable.Map[String, mutable.Map[String, Any]] = (userIds zip devicesToInit).toMap.to(collection.mutable.Map)

	val devicesInitialized: ListBuffer[mutable.Map[String, Any]] = ListBuffer.empty[mutable.Map[String, Any]]

	val devicesActivated: ListBuffer[mutable.Map[String, Any]] = ListBuffer.empty[mutable.Map[String, Any]]

	val scnDeviceActivationInit: ScenarioBuilder = scenario("scnDeviceActivationInit")
		.feed(devicesToInit.map(value => value.toMap).queue)
		.exec(http("PowerAuth - init activation")
			.post("/rest/v3/activation/init")
			.body(StringBody(session => {
				s"""{
			    "requestObject": {
					  "activationOtpValidation": "NONE",
						"applicationId": "${clientConfigObject.get("applicationId").asInstanceOf[Long]}",
						"userId": "${session("userId").as[String]}"
					}
				}"""
			}
			))
			.check(
				jsonPath("$.status").saveAs("status")
			)
			.check(
				jsonPath("$.responseObject.activationCode").saveAs("activationCode")
			)
			.check(
				jsonPath("$.responseObject.activationId").saveAs("activationId")
			)
			.check(
				jsonPath("$.responseObject.activationSignature").saveAs("activationSignature")
			)
		)
		.exec(session => {
			val userId = session("userId").as[String]

			// Prepare activation key and secret
			val applicationSecret = ConfigurationUtil.getApplicationSecret(clientConfigObject).getBytes(StandardCharsets.UTF_8)

			val masterPublicKey = ConfigurationUtil.getMasterKey(clientConfigObject, stepLogger).asInstanceOf[ECPublicKey]
			val eciesEncryptorL1 = eciesFactory.getEciesEncryptorForApplication(masterPublicKey, applicationSecret, EciesSharedInfo1.APPLICATION_SCOPE_GENERIC)
			val eciesEncryptorL2 = eciesFactory.getEciesEncryptorForApplication(masterPublicKey, applicationSecret, EciesSharedInfo1.ACTIVATION_LAYER_2)

			val deviceKeyPair = activation.generateDeviceKeyPair

			val device: mutable.Map[String, Any] = devicesByUserIdMap(userId) ++
				Map(
					"activationCode" -> session("activationCode").as[String],
					"activationId" -> session("activationId").as[String],
					"activationSignature" -> session("activationSignature").as[String],
					"deviceKeyPair" -> deviceKeyPair,
					"eciesEncryptorL1" -> eciesEncryptorL1,
					"eciesEncryptorL2" -> eciesEncryptorL2,
					"password" -> s"Password $userId",
					"resultStatusObject" -> new ResultStatusObject(),
				)

			synchronized {
				devicesByUserIdMap(userId) = device
				devicesInitialized += device
			}
			session
		})

	val deviceIndex: AtomicInteger = new AtomicInteger(0)

	val scnDeviceRegisterApi: ScenarioBuilder = scenario("scnDeviceRegisterApi")
		.exec(session => {
			var index = deviceIndex.incrementAndGet()
			if (index >= devicesInitialized.size) {
				deviceIndex.set(0)
				index = 0
			}
			val userId = devicesInitialized(index)("userId").asInstanceOf[String]
			val data = prepareDeviceActivation(userId)
			session
				.set("userId", userId)
				.set("context", data("context"))
				.set("httpEncryptionHeader", data("httpEncryptionHeader"))
				.set("encryptedRequestL1", data("encryptedRequestL1"))
		})
		//		.rendezVous(NUMBER_OF_DEVICES)
		.exec(http("PowerAuth - create activation")
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
			val userId: String = session("userId").as[String]
			val device: mutable.Map[String, Any] = devicesByUserIdMap(userId)

			val response = new EciesEncryptedResponse(session("encryptedData").as[String], session("mac").as[String])

			val context = session("context").as[ActivationContext]

			val resultStatusObject = prepareActivationStep.processResponse(response, context)
			val deviceActivated = device ++ Map(
				"resultStatusObject" -> resultStatusObject,
			)
			synchronized {
				devicesByUserIdMap(userId) = deviceActivated
				devicesActivated += deviceActivated
			}
			session
		})

	val deviceCreateTokenIndex: AtomicInteger = new AtomicInteger(0)

	val scnCreateTokenApi: ScenarioBuilder = scenario("scnCreateTokenApi")
		.exec(session => {
			var index = deviceCreateTokenIndex.incrementAndGet()
			if (index >= devicesActivated.size) {
				deviceCreateTokenIndex.set(0)
				index = 0
			}
			val device = devicesActivated(index)
			val data = prepareCreateToken(device)
			session
				.set("userId", device("userId").asInstanceOf[String])
				.set("context", data("context"))
				.set("httpAuthorizationHeader", data("httpAuthorizationHeader"))
				.set("requestBytes", data("requestBytes"))
		})
		.exec(http("PowerAuth - create token")
			.post("/pa/v3/token/create")
			.header(PowerAuthSignatureHttpHeader.HEADER_NAME, "${httpAuthorizationHeader}")
			.body(ByteArrayBody(session => {
				session("requestBytes").as[Array[Byte]]
			}))
			.check(jsonPath("$.encryptedData").saveAs("encryptedData"))
			.check(jsonPath("$.mac").saveAs("mac"))
		)
		.exec(session => {
			val response = new EciesEncryptedResponse(session("encryptedData").as[String], session("mac").as[String])
			val context = session("context").as[TokenContext]

			val tokenResponsePayload: TokenResponsePayload = createTokenStep.processResponse(response, new HttpHeaders(), context)

			Map(
				"tokenId" -> tokenResponsePayload.getTokenId,
				"tokenSecret" -> tokenResponsePayload.getTokenSecret,
			)

			session
		})

	setUp(
		scnDeviceActivationInit.inject(
			rampUsers(NUMBER_OF_DEVICES).during(1.minutes)
		).protocols(httpProtocolPowerAuthServer)
			.andThen(
				scnDeviceRegisterApi.inject(
					rampUsers(NUMBER_OF_DEVICES).during(1.minutes)
				).protocols(httpProtocolPowerAuthRestServer)
					.andThen(
						scnCreateTokenApi.inject(
							rampUsers(NUMBER_OF_DEVICES).during(1.minutes)
						).protocols(httpProtocolPowerAuthRestServer)
					)
			)
	)

	def prepareDeviceActivation(userId: String): Map[String, Object] = {
		var device: mutable.Map[String, Any] = mutable.Map() ++ devicesByUserIdMap(userId)

		val model: PrepareActivationStepModel = new PrepareActivationStepModel()
		model.setActivationCode(device("activationCode").asInstanceOf[String])
		model.setActivationName(ConfigurationUtil.getApplicationName(clientConfigObject))
		model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject))
		model.setApplicationSecret(ConfigurationUtil.getApplicationSecret(clientConfigObject))
		model.setDeviceInfo(s"Device Info $userId")
		model.setMasterPublicKey(ConfigurationUtil.getMasterKey(clientConfigObject, stepLogger))
		model.setPassword(device("password").asInstanceOf[String])
		model.setPlatform("devicePlatform")
		model.setVersion("3.1")

		val context = ActivationContext.builder
			.deviceKeyPair(device("deviceKeyPair").asInstanceOf[KeyPair])
			.eciesEncryptorL1(device("eciesEncryptorL1").asInstanceOf[EciesEncryptor])
			.eciesEncryptorL2(device("eciesEncryptorL2").asInstanceOf[EciesEncryptor])
			.modelPrepare(model)
			.password(device("password").asInstanceOf[String])
			.resultStatusObject(device("resultStatusObject").asInstanceOf[ResultStatusObject])
			.stepLogger(stepLogger).build

		val encryptedRequestL1: EciesEncryptedRequest = prepareActivationStep.createRequest(context)

		// Prepare the encryption header
		val header: PowerAuthEncryptionHttpHeader = new PowerAuthEncryptionHttpHeader(model.getApplicationKey, model.getVersion)
		val httpEncryptionHeader: String = header.buildHttpHeader

		device = device ++
			Map(
				"model" -> model
			)

		synchronized {
			devicesByUserIdMap(userId) = device
		}

		Map(
			"httpEncryptionHeader" -> httpEncryptionHeader,
			"encryptedRequestL1" -> encryptedRequestL1,
			"context" -> context,
		)
	}

	def prepareCreateToken(device: mutable.Map[String, Any]): Map[String, Object] = {
		val resultStatusObject = device("resultStatusObject").asInstanceOf[ResultStatusObject]

		val applicationSecret = ConfigurationUtil.getApplicationSecret(clientConfigObject)

		val model = new CreateTokenStepModel
		model.setApplicationKey(ConfigurationUtil.getApplicationKey(clientConfigObject))
		model.setApplicationSecret(applicationSecret)
		model.setPassword(device("password").asInstanceOf[String])
		model.setResultStatusObject(resultStatusObject)
		model.setSignatureType(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)
		model.setVersion("3.1")

		val transportMasterKeyBytes = BaseEncoding.base64.decode(resultStatusObject.getTransportMasterKeyBase64)
		val serverPublicKey = resultStatusObject.getServerPublicKey.asInstanceOf[ECPublicKey]
		val encryptor = eciesFactory.getEciesEncryptorForActivation(serverPublicKey, applicationSecret.getBytes(StandardCharsets.UTF_8), transportMasterKeyBytes, EciesSharedInfo1.CREATE_TOKEN)

		val tokenContext = TokenContext.builder
			.encryptor(encryptor)
			.model(model)
			.password(model.getPassword)
			.resultStatusObject(resultStatusObject)
			.stepLogger(stepLogger)
			.build

		val request = createTokenStep.createRequest(tokenContext)

		val signatureHeader = createTokenStep.createSignatureHeader(request, tokenContext)
		val httpAuthorizationHeader = signatureHeader.buildHttpHeader

		val requestBytes: Array[Byte] = RestClientConfiguration.defaultMapper.writeValueAsBytes(request)

		Map(
			"context" -> tokenContext,
			"httpAuthorizationHeader" -> httpAuthorizationHeader,
			"requestBytes" -> requestBytes,
		)
	}

}
