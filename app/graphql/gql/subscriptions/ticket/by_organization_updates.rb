# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

module Gql::Subscriptions
  class Ticket::ByOrganizationUpdates < BaseSubscription
    description 'Updated organization tickets by filter'

    argument :organization_id, GraphQL::Types::ID, description: 'Filter by organization', loads: Gql::Types::OrganizationType

    field :list_changed, Boolean, description: 'Signals that the organization tickets list has changed'

    requires_permission 'ticket.agent'

    def update(organization:)
      group_ids = ::Ticket.where(organization_id: organization.id).distinct.pluck(:group_id)
      return no_update if group_ids.present? && group_ids.none? { |gid| context.current_user.group_access?(gid, 'read') }

      { list_changed: true }
    end
  end
end
