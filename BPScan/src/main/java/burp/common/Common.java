package burp.common;

import burp.BurpExtender;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import java.io.IOException;
import java.util.Random;


public class Common {
    static HttpClient httpClient = new HttpClient();
    public static String MD5(String src){
        return DigestUtils.md5Hex(src);
    }
    public static String getRandomString(int length){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random=new Random();
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<length;i++){
            int number=random.nextInt(62);
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }
    public static String ceyeResult() throws IOException, InterruptedException {
        Thread.sleep(4000);
        String ceyeToken = YamlReader.getInstance(BurpExtender.getCallbacks()).getString("dnsLog.token");
        String urlParam = "http://api.ceye.io/v1/records?token=" + ceyeToken + "&type=dns&filter=" ;
        GetMethod getMethod = new GetMethod(urlParam);
        getMethod.addRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0");
        httpClient.executeMethod(getMethod);
        String responseBodyAsString = getMethod.getResponseBodyAsString();
        JSONObject content = JSONObject.parseObject(responseBodyAsString);
        String data = String.valueOf(content.get("data"));
        return data;
    }
}
