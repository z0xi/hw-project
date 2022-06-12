import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class SocketServer {

    public static void main(String[] args) {
        try {
            //参考自https://blog.csdn.net/qq_43646059/article/details/116307127
            // 创建服务端socket
            ServerSocket serverSocket = new ServerSocket(8888);

            // 创建客户端socket
            Socket socket = new Socket();
            // 监听客户端
            socket = serverSocket.accept();
            InputStream is=null;
            InputStreamReader isr=null;
            BufferedReader br=null;
            try {
                is = socket.getInputStream();
                isr = new InputStreamReader(is);
                br = new BufferedReader(isr);

                String info = null;
                //info为“success”时，验证成功，为fail时，验证失败
                while((info=br.readLine())!=null){
                    System.out.println(info);
                }
                socket.shutdownInput();
            } catch (Exception e) {
                // TODO: handle exception
            } finally{
                //关闭资源
                try {
                    if(br!=null)
                        br.close();
                    if(isr!=null)
                        isr.close();
                    if(is!=null)
                        is.close();
                    if(socket!=null)
                        socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            // InetAddress address=socket.getInetAddress();
            // System.out.println("当前客户端的IP："+address.getHostAddress());
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
    }

}
