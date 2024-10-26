import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileDescriptor

class MyVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    //private lateinit var socket: Socket

    external fun startVpnNative(fileDescriptor: FileDescriptor): Int

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Create a VPN interface and configure it
        val builder = Builder()
        builder.setMtu(1500)
        builder.addAddress("10.0.0.2", 24) // Local IP for VPN interface
        builder.addDnsServer("8.8.8.8")    // DNS server
        builder.addRoute("0.0.0.0", 0)     // Route all traffic through VPN

        vpnInterface = builder.establish()
        vpnInterface?.fileDescriptor?.let { fd ->
            Thread { startVpnNative(fd) }.start()
        }

        // Start a thread to handle VPN traffic redirection
        //Thread {
        //    handleVpnTrafficInJava()
        //}.start()

        return START_STICKY
    }

    override fun onDestroy() {
        vpnInterface?.close()
        //socket.close()
    }

    /*
    private fun handleVpnTrafficInJava() {
        try {
            // Establish connection to the remote server acting as a transparent proxy
            socket = Socket()
            socket.connect(InetSocketAddress("YOUR_SERVER_IP", 8080)) // Replace YOUR_SERVER_IP with your server IP address

            val vpnInput = FileInputStream(vpnInterface?.fileDescriptor)
            val vpnOutput = FileOutputStream(vpnInterface?.fileDescriptor)
            val serverInput = socket.getInputStream()
            val serverOutput = socket.getOutputStream()

            val buffer = ByteArray(32767)

            while (true) {
                // Read packet from the VPN interface
                val length = vpnInput.read(buffer)
                if (length > 0) {
                    // Forward packet to the server
                    serverOutput.write(buffer, 0, length)
                    serverOutput.flush()
                }

                // Read response from the server and forward it back to VPN interface
                val serverLength = serverInput.read(buffer)
                if (serverLength > 0) {
                    vpnOutput.write(buffer, 0, serverLength)
                    vpnOutput.flush()
                }
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }
     */
}
