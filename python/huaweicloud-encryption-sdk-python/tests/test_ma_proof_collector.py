import pytest

from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException
from huaweicloud_encryptionsdk.proof.attestation_document import AttestationDocument
from huaweicloud_encryptionsdk.proof.collector.ma_proof_collector import MaProofCollector
from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo


class TestMaProofCollector:

    def _make_proof_info(self):
        return ProofInfo(type=4)

    def test_inference_pool_id(self, monkeypatch):
        """推理场景：读 LWS_LEADER_ADDRESS，按 . 分割取最后一段"""
        monkeypatch.setenv(
            "LWS_LEADER_ADDRESS",
            "infer-41-1d26-4b54-a0d5-65c90ca7d603-4c7bc-role-0-0"
            ".infer-41-1d26-4b54-a0d5-65c90ca7d603-4c7bc-role-0"
            ".pool-71948f11-abaa-4a48-be79-60c64bae36bb",
        )
        monkeypatch.delenv("MA_JOB_NAME", raising=False)

        doc = MaProofCollector().collect(self._make_proof_info())
        assert doc.modelarts_pool_id == "pool-71948f11-abaa-4a48-be79-60c64bae36bb"
        assert doc.modelarts_job_id is None

    def test_training_job_id(self, monkeypatch):
        """训练场景：读 MA_JOB_NAME，去掉前缀 modelarts-"""
        monkeypatch.setenv("MA_JOB_NAME", "modelarts-job-16a26dfa-6ac4-4c89-b9ea-aba37b28e1ac")
        monkeypatch.delenv("LWS_LEADER_ADDRESS", raising=False)

        doc = MaProofCollector().collect(self._make_proof_info())
        assert doc.modelarts_job_id == "job-16a26dfa-6ac4-4c89-b9ea-aba37b28e1ac"
        assert doc.modelarts_pool_id is None

    def test_both_env_vars(self, monkeypatch):
        """两个环境变量都存在，两个字段都填充"""
        monkeypatch.setenv("LWS_LEADER_ADDRESS", "pod1.pod2.pool-abc123")
        monkeypatch.setenv("MA_JOB_NAME", "modelarts-job-xyz")

        doc = MaProofCollector().collect(self._make_proof_info())
        assert doc.modelarts_pool_id == "pool-abc123"
        assert doc.modelarts_job_id == "job-xyz"

    def test_no_env_vars_throws(self, monkeypatch):
        """两个环境变量都不存在，抛异常"""
        monkeypatch.delenv("LWS_LEADER_ADDRESS", raising=False)
        monkeypatch.delenv("MA_JOB_NAME", raising=False)

        with pytest.raises(HuaweicloudException):
            MaProofCollector().collect(self._make_proof_info())

    def test_job_id_without_prefix(self, monkeypatch):
        """MA_JOB_NAME 不以 modelarts- 开头，原样返回"""
        monkeypatch.setenv("MA_JOB_NAME", "custom-job-123")
        monkeypatch.delenv("LWS_LEADER_ADDRESS", raising=False)

        doc = MaProofCollector().collect(self._make_proof_info())
        assert doc.modelarts_job_id == "custom-job-123"
