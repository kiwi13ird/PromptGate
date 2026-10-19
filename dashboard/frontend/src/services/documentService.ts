import { gatewayApi } from '@/src/api';
import { mapDocumentDto } from '@/src/api/mappers';
import type { DocumentStatus } from '@/src/types/policy';

export const documentService = {
  async getDocuments(signal?: AbortSignal) {
    return (await gatewayApi.getDocuments(signal)).map(mapDocumentDto);
  },
  async registerDocument(file: File, signal?: AbortSignal) {
    return mapDocumentDto(await gatewayApi.registerDocument(file, signal));
  },
  async changeDocumentStatus(
    documentId: string,
    status: DocumentStatus,
    signal?: AbortSignal,
  ) {
    return mapDocumentDto(
      await gatewayApi.changeDocumentStatus(documentId, status, signal),
    );
  },
};
