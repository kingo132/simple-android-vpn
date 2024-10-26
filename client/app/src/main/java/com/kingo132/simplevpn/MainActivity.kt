package com.kingo132.simplevpn

import MyVpnService
import android.content.Intent
import android.net.VpnService
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import com.kingo132.simplevpn.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
        binding.sampleText.text = stringFromJNI()

        val startVpnButton: Button = findViewById(R.id.start_vpn_button)
        val stopVpnButton: Button = findViewById(R.id.stop_vpn_button)

        startVpnButton.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnActivityResultLauncher.launch(intent)
            } else {
                startVpnService()
            }
        }

        stopVpnButton.setOnClickListener {
            stopVpnService()
        }
    }

    /**
     * A native method that is implemented by the 'simplevpn' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    private val vpnActivityResultLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, MyVpnService::class.java)
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, MyVpnService::class.java)
        stopService(intent)
    }

    companion object {
        // Used to load the 'simplevpn' library on application startup.
        init {
            System.loadLibrary("simplevpn")
        }

        const val VPN_REQUEST_CODE = 100
    }
}