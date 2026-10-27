import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.maven.artifact.versioning.ComparableVersion;
public class MavenComparisonServer {
    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);
        String line;
        while ((line = in.readLine()) != null) {
            try {
                String[] p=line.split("\\t",-1);
                if(p.length!=2)throw new IllegalArgumentException();
                String a=new String(Base64.getDecoder().decode(p[0]),StandardCharsets.UTF_8);
                String b=new String(Base64.getDecoder().decode(p[1]),StandardCharsets.UTF_8);
                out.println(Integer.signum(new ComparableVersion(a).compareTo(new ComparableVersion(b))));
            } catch(Exception e) { out.println("ERROR"); }
        }
    }
}
