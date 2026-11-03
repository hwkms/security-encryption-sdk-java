package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.encryptionsdk.proof.collector.MaProofCollector;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * MaProofCollector 单元测试。
 *
 * 通过子类覆盖 getEnv() 方法来模拟环境变量，避免反射 hack。
 */
public class MaProofCollectorTest {

    private static class TestableMaProofCollector extends MaProofCollector {
        private final Map<String, String> envMap = new HashMap<>();

        public void setEnv(String key, String value) {
            envMap.put(key, value);
        }

        public void clearEnv(String key) {
            envMap.remove(key);
        }

        @Override
        protected String getEnv(String name) {
            return envMap.get(name);
        }
    }

    @Test
    public void testInferencePoolId() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS",
            "infer-41-1d26-4b54-a0d5-65c90ca7d603-4c7bc-role-0-0.infer-41-1d26-4b54-a0d5-65c90ca7d603-4c7bc-role-0.pool-71948f11-abaa-4a48-be79-60c64bae36bb");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("pool-71948f11-abaa-4a48-be79-60c64bae36bb", doc.getModelartsPoolId());
        assertNull(doc.getModelartsJobId());
    }

    @Test
    public void testTrainingJobId() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "modelarts-job-16a26dfa-6ac4-4c89-b9ea-aba37b28e1ac");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("job-16a26dfa-6ac4-4c89-b9ea-aba37b28e1ac", doc.getModelartsJobId());
        assertNull(doc.getModelartsPoolId());
    }

    @Test
    public void testBothEnvVars() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "pod1.pod2.pool-abc123");
        collector.setEnv("MA_JOB_NAME", "modelarts-job-xyz");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("pool-abc123", doc.getModelartsPoolId());
        assertEquals("job-xyz", doc.getModelartsJobId());
    }

    @Test(expected = HuaweicloudException.class)
    public void testNoEnvVarsThrows() {
        TestableMaProofCollector collector = new TestableMaProofCollector();

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        collector.collect(proofInfo);
    }

    @Test
    public void testJobIdWithoutPrefix() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "custom-job-123");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("custom-job-123", doc.getModelartsJobId());
    }

    @Test
    public void testEmptyLwsLeaderAddress() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "");
        collector.setEnv("MA_JOB_NAME", "modelarts-job-abc");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertNull(doc.getModelartsPoolId());
        assertEquals("job-abc", doc.getModelartsJobId());
    }

    @Test
    public void testEmptyMaJobName() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "pod1.pool-xyz");
        collector.setEnv("MA_JOB_NAME", "");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("pool-xyz", doc.getModelartsPoolId());
        assertNull(doc.getModelartsJobId());
    }

    @Test
    public void testLwsLeaderAddressSingleSegment() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "single-segment-no-dot");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("single-segment-no-dot", doc.getModelartsPoolId());
    }

    @Test
    public void testLwsLeaderAddressMultipleDots() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "a.b.c.d.e.pool-final");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("pool-final", doc.getModelartsPoolId());
    }

    @Test
    public void testMaJobNameOnlyPrefix() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "modelarts-");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("", doc.getModelartsJobId());
    }

    @Test
    public void testMaJobNameMultiplePrefixes() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "modelarts-modelarts-job-double");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("modelarts-job-double", doc.getModelartsJobId());
    }

    @Test
    public void testMaJobNameCaseSensitive() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "ModelArts-job-case");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("ModelArts-job-case", doc.getModelartsJobId());
    }

    @Test
    public void testLwsLeaderAddressTrailingDot() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "pod1.pool-trailing.");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        // Java split() removes trailing empty strings, so last segment is "pool-trailing"
        assertEquals("pool-trailing", doc.getModelartsPoolId());
    }

    @Test
    public void testBothEnvVarsEmpty() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "");
        collector.setEnv("MA_JOB_NAME", "");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();

        try {
            collector.collect(proofInfo);
            fail("Expected HuaweicloudException");
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().contains("neither"));
        }
    }

    @Test
    public void testPoolIdWithSpecialCharacters() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("LWS_LEADER_ADDRESS", "pod1.pool-with-dashes_and_underscores");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("pool-with-dashes_and_underscores", doc.getModelartsPoolId());
    }

    @Test
    public void testJobIdWithSpecialCharacters() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        collector.setEnv("MA_JOB_NAME", "modelarts-job-with-dashes_and_underscores");

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals("job-with-dashes_and_underscores", doc.getModelartsJobId());
    }

    @Test
    public void testLongPoolId() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        String longPoolId = "pool-" + "a".repeat(100);
        collector.setEnv("LWS_LEADER_ADDRESS", "pod1." + longPoolId);

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals(longPoolId, doc.getModelartsPoolId());
    }

    @Test
    public void testLongJobId() {
        TestableMaProofCollector collector = new TestableMaProofCollector();
        String longJobId = "job-" + "b".repeat(100);
        collector.setEnv("MA_JOB_NAME", "modelarts-" + longJobId);

        ProofInfo proofInfo = ProofInfo.builder().type(4).build();
        AttestationDocument doc = collector.collect(proofInfo);

        assertEquals(longJobId, doc.getModelartsJobId());
    }
}
