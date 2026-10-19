import { gatewayApi } from '@/src/api';
import { mapAuditLogDto, mapPageDto } from '@/src/api/mappers';
import type { AuditFilters } from '@/src/types/audit';

export const auditService = {
  async getLogs(filters: AuditFilters, signal?: AbortSignal) {
    return mapPageDto(
      await gatewayApi.getAuditLogs(filters, signal),
      mapAuditLogDto,
    );
  },
};
