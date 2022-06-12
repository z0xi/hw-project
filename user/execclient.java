package test;
 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
public class testProcess {
public static void main(String[]args) throws IOException, InterruptedException{
	//参考自https://blog.csdn.net/xqhadoop/article/details/62237086
	Runtime r=Runtime.getRuntime();
	Process p=r.exec("./client");
	InputStream is=p.getInputStream();
	InputStreamReader ir=new InputStreamReader(is);
	BufferedReader br=new BufferedReader(ir);
	String str=null;
	while((str=br.readLine())!=null){
		System.out.println(str);
	}
	//获取进程的返回值,为0正常,为2出现问题
    int ret=p.waitFor();
    int exit_v=p.exitValue();
    System.out.println("return value:"+ret);
   System.out.println("exit value:"+exit_v);
 }
}