package com.bomerang;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.util.*;
import java.util.regex.*;
import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

/** Numeric release range policy. Does not implement all Maven ComparableVersion semantics. */
public class MavenVersionSelector {
    private static final Pattern NUMBER = Pattern.compile("[0-9]+(?:\\.[0-9]+)*");
    private static final Pattern INTERVAL = Pattern.compile("([\\[(])([^\\[\\]()]*)([\\])])");
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final Map<String, Metadata> cache = new HashMap<>();
    private final String repository;
    public MavenVersionSelector() {
        String configured = System.getenv("BOMERANG_MAVEN_REPO_URL");
        repository = configured == null || configured.isBlank() ? "https://repo.maven.apache.org/maven2" : configured.replaceAll("/+$", "");
    }
    public static boolean isRange(String value) { return value != null && (value.trim().startsWith("[") || value.trim().startsWith("(")); }
    static int compare(String a, String b) {
        if (!NUMBER.matcher(a).matches() || !NUMBER.matcher(b).matches()) throw new IllegalArgumentException("Non-numeric version");
        String[] aa=a.split("\\."), bb=b.split("\\.");
        for(int i=0;i<Math.max(aa.length,bb.length);i++) {
            int c=new BigInteger(i<aa.length?aa[i]:"0").compareTo(new BigInteger(i<bb.length?bb[i]:"0"));
            if(c!=0)return c;
        }
        return 0;
    }
    private static List<String[]> intervals(String input) {
        List<String[]> result=new ArrayList<>(); String rest=input.trim();
        while(!rest.isEmpty()) {
            Matcher m=INTERVAL.matcher(rest);
            if(!m.lookingAt())throw new IllegalArgumentException("Unsupported Maven range: "+input);
            String[] parts=m.group(2).split(",",-1); String lo,hi;
            if(parts.length==1 && m.group(1).equals("[") && m.group(3).equals("]"))lo=hi=parts[0].trim();
            else if(parts.length==2){lo=parts[0].trim();hi=parts[1].trim();}
            else throw new IllegalArgumentException("Invalid interval");
            if(!lo.isEmpty())compare(lo,lo); else if(!m.group(1).equals("("))throw new IllegalArgumentException("Invalid open bound");
            if(!hi.isEmpty())compare(hi,hi); else if(!m.group(3).equals(")"))throw new IllegalArgumentException("Invalid open bound");
            if(parts.length==1 && lo.isEmpty())throw new IllegalArgumentException("Empty exact version");
            if(!lo.isEmpty()&&!hi.isEmpty()&&(compare(lo,hi)>0 || compare(lo,hi)==0 && (!m.group(1).equals("[")||!m.group(3).equals("]"))))throw new IllegalArgumentException("Empty range");
            result.add(new String[]{m.group(1),lo,hi,m.group(3)}); rest=rest.substring(m.end()).trim();
            if(!rest.isEmpty()) { if(!rest.startsWith(","))throw new IllegalArgumentException("Invalid union");rest=rest.substring(1).trim();if(rest.isEmpty())throw new IllegalArgumentException("Trailing comma"); }
        }
        if(result.isEmpty())throw new IllegalArgumentException("Empty range");return result;
    }
    static String latest(String spec, List<String> versions) {
        List<String[]> bounds=intervals(spec);String selected=null;
        for(String version:versions) {
            if(!NUMBER.matcher(version).matches())continue;
            for(String[] b:bounds) {
                int low=b[1].isEmpty()?1:compare(version,b[1]), high=b[2].isEmpty()?-1:compare(version,b[2]);
                if((low>0 || low==0 && b[0].equals("[")) && (high<0 || high==0 && b[3].equals("]"))) {
                    if(selected==null || compare(version,selected)>0 || compare(version,selected)==0 && version.length()<selected.length())selected=version;
                    break;
                }
            }
        }
        if(selected==null)throw new IllegalArgumentException("No matching numeric release");return selected;
    }
    public boolean resolve(DependencyNode node) {
        if(!isRange(node.getVersion()))return !"unresolved".equals(node.getVersionStatus());
        try {
            intervals(node.getVersion());String group=node.getGroupId(), name=node.getArtifactId();
            if(group==null||name==null||!group.matches("[A-Za-z0-9_.-]+")||!name.matches("[A-Za-z0-9_.-]+"))throw new IllegalArgumentException("Invalid coordinates");
            String url=repository+"/"+group.replace('.','/')+"/"+name+"/maven-metadata.xml";
            Metadata metadata=cache.get(url);
            if(metadata==null) {
                HttpRequest request=HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(15)).GET().build();
                HttpResponse<byte[]> response=http.send(request,HttpResponse.BodyHandlers.ofByteArray());
                if(response.statusCode()!=200)throw new IllegalStateException("Metadata HTTP "+response.statusCode());
                DocumentBuilderFactory f=DocumentBuilderFactory.newInstance();f.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);f.setFeature("http://xml.org/sax/features/external-general-entities",false);f.setFeature("http://xml.org/sax/features/external-parameter-entities",false);f.setXIncludeAware(false);f.setExpandEntityReferences(false);
                Document doc=f.newDocumentBuilder().parse(new ByteArrayInputStream(response.body()));
                List<String> versions=new ArrayList<>();NodeList nodes=doc.getElementsByTagName("version");
                for(int i=0;i<nodes.getLength();i++)if(nodes.item(i).getParentNode().getNodeName().equals("versions"))versions.add(nodes.item(i).getTextContent().trim());
                byte[] hash=java.security.MessageDigest.getInstance("SHA-256").digest(response.body());
                metadata=new Metadata(versions,Instant.now().toString(),HexFormat.of().formatHex(hash));cache.put(url,metadata);
            }
            node.selectVersion(latest(node.getVersion(),metadata.versions),url,metadata.at,metadata.hash);return true;
        } catch(InterruptedException e){Thread.currentThread().interrupt();node.failVersionResolution("Interrupted");return false;}
        catch(Exception e){node.failVersionResolution(e.getClass().getSimpleName()+": "+e.getMessage());return false;}
    }
    private static final class Metadata {
        final List<String> versions;final String at,hash;
        Metadata(List<String> v,String a,String h){versions=v;at=a;hash=h;}
    }
}
