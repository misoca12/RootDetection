package com.misoca.rootdetection

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.TextView
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.safetynet.SafetyNet
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.safetynet.SafetyNetApi
import org.json.JSONObject






class MainActivity : AppCompatActivity() {

    lateinit var text :TextView
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        text = findViewById<TextView>(android.R.id.text1)
    }

    override fun onResume() {
        super.onResume()
        if (GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(this) == ConnectionResult.SUCCESS) {
            val nonceData = "なんすなんすなんす: " + System.currentTimeMillis()
            val nonce = getRequestNonce(nonceData)
            SafetyNet.getClient(this).attest(nonce, BuildConfig.API_KEY).run {
                addOnSuccessListener(this@MainActivity, { attestationResponse: SafetyNetApi.AttestationResponse ->
                    val jwtSplit = attestationResponse.jwsResult.split(".")
                    // jwt[0]=header jwt[1]=body jwt[2]= signature
                    val jwtBody = String(Base64.decode(jwtSplit[1], Base64.DEFAULT))
                    val jwtBodyJson = JSONObject(jwtBody)
                    val ctsProfileMatch = jwtBodyJson.getBoolean("ctsProfileMatch")
                    val basicIntegrity = jwtBodyJson.getBoolean("basicIntegrity")
                    var result = "Root detect:${if (!ctsProfileMatch && !basicIntegrity) "detection" else "None"}\n"
                    result += "${jwtBodyJson.toString(4)}"
                    text.text = result
                })
                addOnFailureListener(this@MainActivity, { e ->
                    if (e is ApiException) {
                        // An error with the Google Play Services API contains some additional details.
                        text.text = "Error: ${CommonStatusCodes.getStatusCodeString(e.statusCode)}:${e.statusMessage}"
                    } else {
                        // A different, unknown type of error occurred.
                        text.text = "ERROR! ${e.message}"
                    }
                })
            }
        } else {
            text.text = "Google Play開発者サービスが古いから更新してね☆"
        }
    }

    fun getRequestNonce(data: String): ByteArray {
        val byteStream = ByteArrayOutputStream()
        val bytes = ByteArray(24)
        SecureRandom().nextBytes(bytes)
        try {
            byteStream.write(bytes)
            byteStream.write(data.toByteArray())
        } catch (e: IOException) {
            Log.e("tag", "ERROR! ${e.message}")
        }
        return byteStream.toByteArray()
    }
}
