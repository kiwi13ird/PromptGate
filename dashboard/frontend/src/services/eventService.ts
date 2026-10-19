import { gatewayApi } from '@/src/api';
import { mapPageDto, mapSecurityEventDto } from '@/src/api/mappers';
import type {
  EventFilters,
  IncidentStatus,
  PaginatedResult,
  SecurityEvent,
} from '@/src/types/event';

export const eventService = {
  async getEvents(
    filters: EventFilters,
    signal?: AbortSignal,
  ): Promise<PaginatedResult<SecurityEvent>> {
    return mapPageDto(
      await gatewayApi.getEvents(filters, signal),
      mapSecurityEventDto,
    );
  },
  async getEventById(
    eventId: string,
    signal?: AbortSignal,
  ): Promise<SecurityEvent | null> {
    const result = await gatewayApi.getEvent(eventId, signal);
    return result ? mapSecurityEventDto(result) : null;
  },
  async updateStatus(
    eventId: string,
    status: IncidentStatus,
    signal?: AbortSignal,
  ) {
    return mapSecurityEventDto(
      await gatewayApi.updateEventStatus(eventId, status, signal),
    );
  },
  async assign(eventId: string, assignee: string, signal?: AbortSignal) {
    return mapSecurityEventDto(
      await gatewayApi.assignEvent(eventId, assignee, signal),
    );
  },
  async addNote(eventId: string, content: string, signal?: AbortSignal) {
    return mapSecurityEventDto(
      await gatewayApi.addEventNote(eventId, content, signal),
    );
  },
};
