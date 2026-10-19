import { gatewayApi } from '@/src/api';
import { mapPolicyCapabilitiesDto, mapPolicyDto, mapPolicyVersionDto } from '@/src/api/mappers';
import type { PolicyAction } from '@/src/types/policy';

export const policyService = {
  async getPolicies(signal?: AbortSignal) {
    return (await gatewayApi.getPolicies(signal)).map(mapPolicyDto);
  },
  async getCapabilities(signal?: AbortSignal) {
    return mapPolicyCapabilitiesDto(await gatewayApi.getPolicyCapabilities(signal));
  },
  async getPolicyHistory(policyId: string, signal?: AbortSignal) {
    return (await gatewayApi.getPolicyHistory(policyId, signal)).map(
      mapPolicyVersionDto,
    );
  },
  async createPolicy(
    target: string,
    action: PolicyAction,
    signal?: AbortSignal,
  ) {
    return mapPolicyDto(await gatewayApi.createPolicy(target, action, signal));
  },
  async updatePolicy(
    policyId: string,
    action: PolicyAction,
    expectedVersion: number,
    signal?: AbortSignal,
  ) {
    return mapPolicyDto(
      await gatewayApi.updatePolicy(policyId, action, expectedVersion, signal),
    );
  },
  async changePolicyStatus(
    policyId: string,
    enabled: boolean,
    expectedVersion: number,
    signal?: AbortSignal,
  ) {
    return mapPolicyDto(
      await gatewayApi.changePolicyStatus(
        policyId,
        enabled,
        expectedVersion,
        signal,
      ),
    );
  },
};
