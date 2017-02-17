import org.junit.Assert;
import org.junit.Test;

/**
 * Created by randy on 2/17/2017.
 */
public class SplitByDelimiterTEST {

    @Test
    public void splitSingleStringTEST() {
        String delim = "<!!>";
        String regExSplitBy = "[<!!>]+";   //the brackets mean a group and the + means all the letters together

        String p1 = "fname";
        String p2 = "lname";
        String combined = p1 + delim + p2;
        String[] parts = combined.split(delim);
        Assert.assertTrue(p1.equals(parts[0]));
        Assert.assertTrue(p2.equals(parts[1]));
    }
}
