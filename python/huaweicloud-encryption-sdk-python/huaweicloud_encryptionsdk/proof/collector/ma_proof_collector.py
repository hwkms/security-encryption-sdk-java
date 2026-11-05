import os

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.proof_collector import ProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo


LWS_LEADER_ADDRESS_ENV = "LWS_LEADER_ADDRESS"
MA_JOB_NAME_ENV = "MA_JOB_NAME"
MODELARTS_PREFIX = "modelarts-"


class MaProofCollector(ProofCollector):
    """ModelArts (MA) 接入点证明收集器。

    根据环境变量自动判断场景：
    - 推理场景：读 LWS_LEADER_ADDRESS，按 . 分割取最后一段作为 pool_id
    - 训练场景：读 MA_JOB_NAME，去掉前缀 modelarts- 得到 job_id
    """

    def collect(self, proof_info: ProofInfo) -> AttestationDocument:
        pool_id = self._extract_pool_id()
        job_id = self._extract_job_id()

        if pool_id is None and job_id is None:
            raise HuaweicloudException(
                f"Failed to collect MA proof: neither {LWS_LEADER_ADDRESS_ENV} "
                f"nor {MA_JOB_NAME_ENV} found"
            )

        return AttestationDocument(
            modelarts_pool_id=pool_id,
            modelarts_job_id=job_id,
        )

    @staticmethod
    def _extract_pool_id() -> str | None:
        addr = os.environ.get(LWS_LEADER_ADDRESS_ENV, "")
        if not addr:
            return None
        return addr.split(".")[-1]

    @staticmethod
    def _extract_job_id() -> str | None:
        job_name = os.environ.get(MA_JOB_NAME_ENV, "")
        if not job_name:
            return None
        if job_name.startswith(MODELARTS_PREFIX):
            return job_name[len(MODELARTS_PREFIX):]
        return job_name
