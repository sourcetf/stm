/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod get;
pub mod patch;
pub mod set;

use crate::{context::ScimContext, error::Result};
use registry::{
    schema::{
        enums::{Locale, Permission, TimeZone},
        structs::{EmailAlias, Permissions, PermissionsList, UserAccount},
    },
    types::{EnumImpl, list::List},
};
use scim_proto::{
    ResourceType,
    attributes::AttributeSelection,
    etag::weak_etag,
    message::error::Error,
    schema::{
        Meta,
        user::{Email, GroupRef, Name, USER_SCHEMA, User},
    },
};
use serde_json::Value;
use types::id::Id;

pub const EMAIL_TYPE_WORK: &str = "work";
pub const DEFAULT_LOCALE: Locale = Locale::EnUS;
pub const GROUP_TYPE_DIRECT: &str = "direct";

impl ScimContext<'_> {
    pub async fn user_to_scim(
        &self,
        id: Id,
        revision: u64,
        account: &UserAccount,
        selection: &AttributeSelection<'_>,
    ) -> Result<Value> {
        let user_name = self.email_address(&account.name, account.domain_id).await?;
        let mut emails = Vec::with_capacity(account.aliases.len() + 1);
        emails.push(Email {
            value: Some(user_name.clone().into()),
            r#type: Some(EMAIL_TYPE_WORK.into()),
            primary: Some(true),
            ..Default::default()
        });
        for alias in account.aliases.values() {
            emails.push(Email {
                value: Some(
                    self.email_address(&alias.name, alias.domain_id)
                        .await?
                        .into(),
                ),
                r#type: Some(EMAIL_TYPE_WORK.into()),
                ..Default::default()
            });
        }

        let groups =
            if account.member_group_ids.is_empty() || selection.excludes(&USER_SCHEMA, "groups") {
                None
            } else {
                let mut groups = Vec::with_capacity(account.member_group_ids.len());
                for group_id in account.member_group_ids.iter() {
                    let display =
                        self.server
                            .try_account(group_id.document_id())
                            .await?
                            .map(|group| {
                                group
                                    .description
                                    .as_deref()
                                    .unwrap_or_else(|| group.name.as_ref())
                                    .to_string()
                            });

                    groups.push(GroupRef {
                        value: Some(group_id.to_string().into()),
                        ref_: Some(self.location(ResourceType::Group, *group_id).into()),
                        display: display.map(Into::into),
                        r#type: Some(GROUP_TYPE_DIRECT.into()),
                    });
                }
                Some(groups)
            };

        let locale = locale_to_scim(account.locale.as_str());
        let user = User {
            id: Some(id.to_string().into()),
            external_id: account.external_id.as_deref().map(Into::into),
            user_name: Some(user_name.into()),
            name: account.description.as_deref().map(|description| Name {
                formatted: Some(description.into()),
                ..Default::default()
            }),
            display_name: account.description.as_deref().map(Into::into),
            active: if selection.excludes(&USER_SCHEMA, "active") {
                None
            } else {
                Some(self.is_active(account).await?)
            },
            emails: Some(emails),
            locale: Some(locale.clone().into()),
            preferred_language: Some(locale.into()),
            timezone: account
                .time_zone
                .as_ref()
                .map(|time_zone| time_zone.as_str().into()),
            groups,
            meta: Some(
                Meta::new(ResourceType::User)
                    .with_created(account.created_at.to_string())
                    .with_location(self.location(ResourceType::User, id))
                    .with_version(weak_etag(revision)),
            ),
        };

        let mut value = serde_json::to_value(&user).unwrap_or(Value::Null);
        selection.apply(&USER_SCHEMA, &mut value);

        Ok(value)
    }

    pub async fn set_user_name(&self, account: &mut UserAccount, user_name: &str) -> Result<()> {
        let (local_part, domain) = self.resolve_address(user_name, "userName").await?;

        account.name = local_part;
        account.domain_id = Id::from(domain.id);
        account.member_tenant_id = match self.tenant_id() {
            Some(tenant_id) => Some(Id::from(tenant_id)),
            None => domain.id_tenant.map(Id::from),
        };

        Ok(())
    }

    pub async fn set_emails(&self, account: &mut UserAccount, emails: &[Email<'_>]) -> Result<()> {
        let primary = self.email_address(&account.name, account.domain_id).await?;
        let mut aliases = List::with_capacity(emails.len());

        for email in emails {
            let Some(value) = email.value.as_deref().filter(|value| !value.is_empty()) else {
                continue;
            };

            if value.eq_ignore_ascii_case(&primary) {
                continue;
            }

            let (local_part, domain) = self.resolve_address(value, "emails").await?;

            if domain.id_tenant.map(Id::from) != account.member_tenant_id {
                return Err(Error::invalid_value(format!(
                    "The address '{value}' belongs to a domain in a different tenant."
                ))
                .into());
            }

            let alias = EmailAlias {
                enabled: true,
                name: local_part,
                domain_id: Id::from(domain.id),
                description: None,
            };

            if !aliases.iter().any(|existing| *existing == alias) {
                aliases.push(alias);
            }
        }

        account.aliases = aliases;

        Ok(())
    }
}

pub fn locale_to_scim(locale: &str) -> String {
    locale.replace('_', "-")
}

pub fn set_active(permissions: &mut Permissions, active: bool) {
    const AUTHENTICATE: Permission = Permission::Authenticate;

    match permissions {
        Permissions::Inherit => {
            if !active {
                let mut list = PermissionsList::default();
                list.disabled_permissions.push(AUTHENTICATE);
                *permissions = Permissions::Merge(list);
            }
        }
        Permissions::Merge(list) => {
            if active {
                list.disabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                if list.enabled_permissions.is_empty() && list.disabled_permissions.is_empty() {
                    *permissions = Permissions::Inherit;
                }
            } else {
                list.enabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.disabled_permissions.push(AUTHENTICATE);
            }
        }
        Permissions::Replace(list) => {
            if active {
                list.disabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.enabled_permissions.push(AUTHENTICATE);
            } else {
                list.enabled_permissions
                    .inner_mut()
                    .retain(|permission| *permission != AUTHENTICATE);
                list.disabled_permissions.push(AUTHENTICATE);
            }
        }
    }
}

pub fn set_locale(account: &mut UserAccount, locale: &str) -> Result<()> {
    let value = locale.replace('-', "_");

    account.locale = Locale::parse(&value)
        .or_else(|| Locale::parse(&canonical_locale(&value)))
        .ok_or_else(|| {
            Error::invalid_value(format!(
                "The locale '{locale}' is not supported by this server."
            ))
        })?;

    Ok(())
}

fn canonical_locale(locale: &str) -> String {
    let Some((language, rest)) = locale.split_once('_') else {
        return locale.to_lowercase();
    };
    let (region, modifier) = match rest.split_once('@') {
        Some((region, modifier)) => (region, Some(modifier)),
        None => (rest, None),
    };

    let mut canonical = String::with_capacity(locale.len());
    canonical.extend(language.chars().flat_map(char::to_lowercase));
    canonical.push('_');
    canonical.extend(region.chars().flat_map(char::to_uppercase));

    if let Some(modifier) = modifier {
        canonical.push('@');
        canonical.extend(modifier.chars().flat_map(char::to_lowercase));
    }

    canonical
}

pub fn set_time_zone(account: &mut UserAccount, time_zone: Option<&str>) -> Result<()> {
    account.time_zone = match time_zone {
        Some(time_zone) => Some(TimeZone::parse(time_zone).ok_or_else(|| {
            Error::invalid_value(format!(
                "The time zone '{time_zone}' is not a known IANA time zone identifier."
            ))
        })?),
        None => None,
    };
    Ok(())
}

pub fn display_name(user: &User<'_>) -> Option<String> {
    user.display_name
        .as_deref()
        .filter(|display_name| !display_name.is_empty())
        .map(str::to_string)
        .or_else(|| user.name.as_ref().and_then(Name::composed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merged(enabled: &[Permission], disabled: &[Permission]) -> Permissions {
        let mut list = PermissionsList::default();
        for permission in enabled {
            list.enabled_permissions.push(*permission);
        }
        for permission in disabled {
            list.disabled_permissions.push(*permission);
        }
        Permissions::Merge(list)
    }

    fn is_deactivated(permissions: &Permissions) -> bool {
        match permissions {
            Permissions::Inherit => false,
            Permissions::Merge(list) | Permissions::Replace(list) => list
                .disabled_permissions
                .contains(&Permission::Authenticate),
        }
    }

    #[test]
    fn deactivating_an_inherited_account_creates_a_merge() {
        let mut permissions = Permissions::Inherit;
        set_active(&mut permissions, false);

        assert_eq!(permissions, merged(&[], &[Permission::Authenticate]));
    }

    #[test]
    fn reactivating_collapses_back_to_inherit() {
        let mut permissions = Permissions::Inherit;
        set_active(&mut permissions, false);
        set_active(&mut permissions, true);

        assert_eq!(permissions, Permissions::Inherit);
    }

    #[test]
    fn deactivation_is_idempotent() {
        let mut permissions = Permissions::Inherit;
        set_active(&mut permissions, false);
        set_active(&mut permissions, false);

        assert_eq!(permissions, merged(&[], &[Permission::Authenticate]));
    }

    #[test]
    fn activating_an_inherited_account_is_a_no_op() {
        let mut permissions = Permissions::Inherit;
        set_active(&mut permissions, true);

        assert_eq!(permissions, Permissions::Inherit);
    }

    #[test]
    fn unrelated_customisation_survives_a_deactivation_cycle() {
        let mut permissions = merged(
            &[Permission::ImapAuthenticate],
            &[Permission::Pop3Authenticate],
        );
        set_active(&mut permissions, false);

        assert!(is_deactivated(&permissions));

        set_active(&mut permissions, true);

        assert_eq!(
            permissions,
            merged(
                &[Permission::ImapAuthenticate],
                &[Permission::Pop3Authenticate]
            )
        );
    }

    #[test]
    fn an_enabled_authenticate_is_removed_on_deactivation() {
        let mut permissions = merged(&[Permission::Authenticate], &[]);
        set_active(&mut permissions, false);

        assert_eq!(permissions, merged(&[], &[Permission::Authenticate]));
    }

    #[test]
    fn replace_grants_authenticate_on_activation() {
        let mut list = PermissionsList::default();
        list.disabled_permissions.push(Permission::Authenticate);
        let mut permissions = Permissions::Replace(list);

        set_active(&mut permissions, true);

        match &permissions {
            Permissions::Replace(list) => {
                assert!(list.enabled_permissions.contains(&Permission::Authenticate));
                assert!(
                    !list
                        .disabled_permissions
                        .contains(&Permission::Authenticate)
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replace_is_never_collapsed_to_inherit() {
        let mut permissions = Permissions::Replace(PermissionsList::default());
        set_active(&mut permissions, true);

        assert!(matches!(permissions, Permissions::Replace(_)));
    }

    #[test]
    fn locales_round_trip_between_scim_and_stalwart() {
        let mut account = UserAccount::default();

        for (scim, expected) in [
            ("en-US", Locale::EnUS),
            ("EN-us", Locale::EnUS),
            ("de-DE", Locale::DeDE),
            ("en_US", Locale::EnUS),
            ("POSIX", Locale::POSIX),
            ("ca-ES@valencia", Locale::CaESValencia),
            ("CA-es@VALENCIA", Locale::CaESValencia),
        ] {
            set_locale(&mut account, scim).unwrap_or_else(|_| panic!("{scim}"));
            assert_eq!(account.locale, expected, "{scim}");
        }

        assert_eq!(locale_to_scim(Locale::EnUS.as_str()), "en-US");
        assert!(set_locale(&mut account, "not-a-locale").is_err());
    }

    #[test]
    fn time_zones_are_iana_identifiers() {
        let mut account = UserAccount::default();

        set_time_zone(&mut account, Some("America/Los_Angeles")).unwrap();
        assert_eq!(
            account.time_zone.as_ref().map(EnumImpl::as_str),
            Some("America/Los_Angeles")
        );

        set_time_zone(&mut account, None).unwrap();
        assert!(account.time_zone.is_none());
        assert!(set_time_zone(&mut account, Some("Mars/Olympus")).is_err());
    }

    #[test]
    fn display_name_takes_precedence_over_name_formatted() {
        let user = User {
            display_name: Some("Babs Jensen".into()),
            name: Some(Name {
                formatted: Some("Ms. Barbara J Jensen, III".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(display_name(&user).as_deref(), Some("Babs Jensen"));

        let user = User {
            name: Some(Name {
                formatted: Some("Ms. Barbara J Jensen, III".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(
            display_name(&user).as_deref(),
            Some("Ms. Barbara J Jensen, III")
        );
        assert_eq!(display_name(&User::default()), None);

        let user = User {
            name: Some(Name {
                given_name: Some("Barbara".into()),
                family_name: Some("Jensen".into()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(display_name(&user).as_deref(), Some("Barbara Jensen"));
    }
}
