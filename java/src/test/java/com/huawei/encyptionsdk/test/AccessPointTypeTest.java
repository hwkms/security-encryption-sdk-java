package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.enums.AccessPointType;
import org.junit.Assert;
import org.junit.Test;

public class AccessPointTypeTest {

    @Test
    public void testGetDisplayNameByCode_ECS() {
        Assert.assertEquals("ECS", AccessPointType.getDisplayNameByCode(1));
    }

    @Test
    public void testGetDisplayNameByCode_Custom() {
        Assert.assertEquals("Custom", AccessPointType.getDisplayNameByCode(2));
    }

    @Test
    public void testGetDisplayNameByCode_CCE() {
        Assert.assertEquals("CCE", AccessPointType.getDisplayNameByCode(3));
    }

    @Test
    public void testGetDisplayNameByCode_MA() {
        Assert.assertEquals("MA", AccessPointType.getDisplayNameByCode(4));
    }

    @Test
    public void testGetDisplayNameByCode_Unknown() {
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(999));
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(0));
        Assert.assertEquals("Unknown", AccessPointType.getDisplayNameByCode(-1));
    }

    @Test
    public void testEnumValues() {
        Assert.assertEquals(1, AccessPointType.ECS.getCode());
        Assert.assertEquals("ECS", AccessPointType.ECS.getDisplayName());
        Assert.assertEquals(2, AccessPointType.CUSTOM.getCode());
        Assert.assertEquals("Custom", AccessPointType.CUSTOM.getDisplayName());
        Assert.assertEquals(3, AccessPointType.CCE.getCode());
        Assert.assertEquals("CCE", AccessPointType.CCE.getDisplayName());
        Assert.assertEquals(4, AccessPointType.MA.getCode());
        Assert.assertEquals("MA", AccessPointType.MA.getDisplayName());
    }

    @Test
    public void testAllValues() {
        AccessPointType[] values = AccessPointType.values();
        Assert.assertEquals(4, values.length);
    }

    @Test
    public void testValueOf() {
        Assert.assertEquals(AccessPointType.ECS, AccessPointType.valueOf("ECS"));
        Assert.assertEquals(AccessPointType.CUSTOM, AccessPointType.valueOf("CUSTOM"));
        Assert.assertEquals(AccessPointType.CCE, AccessPointType.valueOf("CCE"));
        Assert.assertEquals(AccessPointType.MA, AccessPointType.valueOf("MA"));
    }

    @Test
    public void testName() {
        Assert.assertEquals("ECS", AccessPointType.ECS.name());
        Assert.assertEquals("CUSTOM", AccessPointType.CUSTOM.name());
        Assert.assertEquals("CCE", AccessPointType.CCE.name());
        Assert.assertEquals("MA", AccessPointType.MA.name());
    }

    @Test
    public void testOrdinal() {
        Assert.assertEquals(0, AccessPointType.ECS.ordinal());
        Assert.assertEquals(1, AccessPointType.CUSTOM.ordinal());
        Assert.assertEquals(2, AccessPointType.CCE.ordinal());
        Assert.assertEquals(3, AccessPointType.MA.ordinal());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValueOfInvalid() {
        AccessPointType.valueOf("INVALID");
    }

    @Test
    public void testGetDisplayNameByCodeAllValid() {
        for (AccessPointType type : AccessPointType.values()) {
            String displayName = AccessPointType.getDisplayNameByCode(type.getCode());
            Assert.assertEquals(type.getDisplayName(), displayName);
        }
    }

    @Test
    public void testMaEnumSpecific() {
        AccessPointType ma = AccessPointType.MA;
        Assert.assertEquals(4, ma.getCode());
        Assert.assertEquals("MA", ma.getDisplayName());
        Assert.assertEquals("MA", ma.name());
        Assert.assertEquals(3, ma.ordinal());
    }
}
