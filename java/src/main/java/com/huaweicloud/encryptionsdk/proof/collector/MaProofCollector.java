package com.huaweicloud.encryptionsdk.proof.collector;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollector;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ModelArts (MA) 接入点证明收集器。
 *
 * <p>根据环境变量自动判断场景：
 * <ul>
 *   <li>推理场景：读 {@code LWS_LEADER_ADDRESS}，按 {@code .} 分割取最后一段作为 pool_id</li>
 *   <li>训练场景：读 {@code MA_JOB_NAME}，去掉前缀 {@code modelarts-} 得到 job_id</li>
 * </ul>
 */
public class MaProofCollector implements ProofCollector {

    private static final Logger LOGGER = LoggerFactory.getLogger(MaProofCollector.class);

    private static final String LWS_LEADER_ADDRESS_ENV = "LWS_LEADER_ADDRESS";
    private static final String MA_JOB_NAME_ENV = "MA_JOB_NAME";
    private static final String MODELARTS_PREFIX = "modelarts-";

    @Override
    public AttestationDocument collect(ProofInfo proofInfo) {
        String poolId = extractPoolId();
        String jobId = extractJobId();

        if (poolId == null && jobId == null) {
            throw new HuaweicloudException(String.format(
                "%s: neither %s nor %s found",
                ErrorMessage.COLLECT_PROOF_EXCEPTION.getMessage(),
                LWS_LEADER_ADDRESS_ENV,
                MA_JOB_NAME_ENV));
        }

        LOGGER.info("MA proof collected, poolId={}, jobId={}", poolId, jobId);
        return AttestationDocument.builder()
                .modelartsPoolId(poolId)
                .modelartsJobId(jobId)
                .build();
    }

    /**
     * 推理场景：读 LWS_LEADER_ADDRESS，按 . 分割取最后一段作为 pool_id
     */
    private String extractPoolId() {
        String addr = getEnv(LWS_LEADER_ADDRESS_ENV);
        if (addr == null || addr.isEmpty()) {
            return null;
        }
        String[] parts = addr.split("\\.");
        String poolId = parts[parts.length - 1];
        LOGGER.info("MA inference pool_id from {}: {}", LWS_LEADER_ADDRESS_ENV, poolId);
        return poolId;
    }

    /**
     * 训练场景：读 MA_JOB_NAME，去掉前缀 modelarts- 得到 job_id
     */
    private String extractJobId() {
        String jobName = getEnv(MA_JOB_NAME_ENV);
        if (jobName == null || jobName.isEmpty()) {
            return null;
        }
        String jobId = jobName.startsWith(MODELARTS_PREFIX)
                ? jobName.substring(MODELARTS_PREFIX.length())
                : jobName;
        LOGGER.info("MA training job_id from {}: {}", MA_JOB_NAME_ENV, jobId);
        return jobId;
    }

    /**
     * 获取环境变量（可被子类覆盖以便测试）
     */
    protected String getEnv(String name) {
        return System.getenv(name);
    }
}
