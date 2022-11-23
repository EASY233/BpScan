package burp.common;

import burp.IBurpExtenderCallbacks;

import java.io.PrintWriter;
import java.util.List;


public class ScanJudge {

    private final IBurpExtenderCallbacks callbacks;
    private final PrintWriter stdout;

    public ScanJudge(IBurpExtenderCallbacks callbacks, PrintWriter stdout) {
        this.callbacks = callbacks;
        this.stdout = stdout;
    }

    public boolean isBlackSuffix(String urlpath){
        List<String> urlBlackListSuffix = YamlReader.getInstance(callbacks).getStringList("scan.urlBlackListSuffix");
        String noParameterUrl = urlpath.toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);
        for(String suffix:urlBlackListSuffix){
            if(suffix.toLowerCase().equals(urlSuffix)){
                return true;
            }
        }
        return false;
    }
    public boolean isBlackdomain(String domain){
        List<String> blacklist = YamlReader.getInstance(callbacks).getStringList("scan.blacklist");
        for(String black:blacklist){
            if(domain.contains(black)){
                return true;
            }
        }
        return false;
    }
    public boolean isBlackheader(List<String> resheaders){
        List<String> blackFeatures = YamlReader.getInstance(callbacks).getStringList("scan.blackFeatures");
        for(int i=1;i<resheaders.size();i++){
            for(String Features:blackFeatures){
                if(resheaders.get(i).contains(Features)){
                    return true;
                }
            }
        }
        return false;
    }
}
