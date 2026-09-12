//! Zig source emission for the TL code generator.
//!
//! Takes a validated `Schema` AST and writes deterministic Zig source.
//! Two layouts:
//!
//!   * `emit` — the single-file layout: one `struct` per non-generic
//!     constructor, one tagged `union(enum)` per TL result type, TL
//!     namespaces as nested container structs, functions as request
//!     structs with `serialize` and a `Result` decl. Kept for the golden
//!     test and the build's generated-code compile check.
//!   * `emitSplit` — the committed layout (tree, no monolith): an entry
//!     module (`mod.zig`) that re-exports every declaration with the
//!     same flat surface as the single-file layout, plus content in two
//!     subdirectories: `types/<group>.zig` — result-type unions together
//!     with their constructors, grouped by TL namespace and, for the
//!     root namespace, thematically (`users.zig`, `messages.zig`,
//!     `chats.zig`, …) — and `functions/<namespace>.zig` — the request
//!     structs. `registry.zig` holds the sorted wire-id table. Every
//!     cross-file reference routes through the entry module (`api.User`,
//!     `api.messages.sendMessage`), so declaration paths resolve exactly
//!     as they did in single-file mode.
//!
//! Memory model of the generated code (both layouts): `deserialize`
//! borrows all strings and byte slices from the reader's buffer
//! (zero-copy) and allocates only vector storage with the caller's
//! allocator. Generic combinators (`vector#1cb5c415`, `invokeWith*`
//! wrappers) are intentionally not emitted — `Vector<T>` maps to native
//! slices and wrappers belong to the RPC layer.

const std = @import("std");
const ast = @import("../types.zig");
const Schema = @import("../schema.zig").Schema;
const naming = @import("naming.zig");

/// One emitted source file in split mode.
pub const OutputFile = struct { name: []const u8, src: []const u8 };

pub const Options = struct {
    /// Name of the module the generated code imports for Reader/Writer.
    module_name: []const u8 = "td",
    /// Header comment line describing the source (deterministic).
    source_name: []const u8 = "schema",
    /// Append a test that forces semantic analysis of every generated
    /// declaration (used by the build's generated-code compilation checks).
    self_test: bool = false,
    /// Name of the entry module file in split mode (`emitSplit`, written
    /// at the output root); the `types/`/`functions/` content files import
    /// it back as `api` to qualify cross-file references.
    root_name: []const u8 = "mod.zig",
};

/// Full-name overrides for namespaced result types whose constructors
/// belong with a thematic root group instead of a file of their own
/// (`photos`/`upload`/`storage` hold a handful of media/file types;
/// `stickers.SuggestedShortName` belongs with the sticker types).
const ns_group_override = std.StaticStringMap([]const u8).initComptime(.{
    .{ "photos.Photo", "media" },
    .{ "photos.Photos", "media" },
    .{ "storage.FileType", "files" },
    .{ "stickers.SuggestedShortName", "stickers" },
    .{ "upload.CdnFile", "files" },
    .{ "upload.File", "files" },
    .{ "upload.WebFile", "files" },
});

/// Thematic groups for ROOT-namespace result types: which types/<group>.zig
/// a root result-type union — and every constructor producing it — belongs
/// to. The root namespace carries the bulk of the schema (~1300
/// constructors), so it is subdivided by domain; anything not listed here
/// falls back to `misc`. Keys are TL short names; keep entries sorted and
/// the grouping is deterministic.
const root_type_theme = std.StaticStringMap([]const u8).initComptime(.{
    // Primitives and schema plumbing.
    .{ "Bool", "common" },                  .{ "True", "common" },
    .{ "Null", "common" },                  .{ "Error", "common" },
    .{ "JSONValue", "common" },             .{ "JSONObjectValue", "common" },
    .{ "DataJSON", "common" },              .{ "TextWithEntities", "common" },
    .{ "RestrictionReason", "common" },     .{ "FactCheck", "common" },
    .{ "CodeSettings", "common" },          .{ "InputClientProxy", "common" },
    .{ "InputAppEvent", "common" },         .{ "ReceivedNotifyMessage", "common" },
    // Users and profiles.
    .{ "User", "users" },                   .{ "UserFull", "users" },
    .{ "UserProfilePhoto", "users" },       .{ "UserStatus", "users" },
    .{ "ProfileTab", "users" },             .{ "Username", "users" },
    // Peer references.
    .{ "Peer", "peers" },                   .{ "PeerLocated", "peers" },
    .{ "PeerColor", "peers" },              .{ "InputPeer", "peers" },
    .{ "InputUser", "peers" },              .{ "InputChannel", "peers" },
    .{ "NotifyPeer", "peers" },             .{ "InputNotifyPeer", "peers" },
    .{ "RequestPeerType", "peers" },        .{ "RequestedPeer", "peers" },
    .{ "SendAsPeer", "peers" },             .{ "PeerBlocked", "peers" },
    // Chats, channels and dialogs.
    .{ "Chat", "chats" },                   .{ "ChatFull", "chats" },
    .{ "ChatPhoto", "chats" },              .{ "ChatParticipant", "chats" },
    .{ "ChatParticipants", "chats" },       .{ "ChatInvite", "chats" },
    .{ "ChatInviteImporter", "chats" },     .{ "ChatOnlines", "chats" },
    .{ "ChatAdminRights", "chats" },        .{ "ChatBannedRights", "chats" },
    .{ "ChatAdminWithInvites", "chats" },   .{ "ExportedChatInvite", "chats" },
    .{ "Dialog", "chats" },                 .{ "DialogPeer", "chats" },
    .{ "DialogFilter", "chats" },           .{ "DialogFilterSuggested", "chats" },
    .{ "Folder", "chats" },                 .{ "FolderPeer", "chats" },
    .{ "InputFolderPeer", "chats" },        .{ "SavedDialog", "chats" },
    .{ "DraftMessage", "chats" },           .{ "ForumTopic", "chats" },
    .{ "InputChatlist", "chats" },          .{ "ExportedChatlistInvite", "chats" },
    .{ "DefaultHistoryTTL", "chats" },      .{ "MissingInvitee", "chats" },
    .{ "EncryptedChat", "chats" },          .{ "InputEncryptedChat", "chats" },
    .{ "EncryptedMessage", "chats" },
    // Channel administration.
    .{ "ChannelAdminLogEvent", "channels" },            .{ "ChannelAdminLogEventAction", "channels" },
    .{ "ChannelAdminLogEventsFilter", "channels" },     .{ "ChannelParticipant", "channels" },
    .{ "ChannelLocation", "channels" },                 .{ "ChannelMessagesFilter", "channels" },
    .{ "ChannelParticipantsFilter", "channels" },
    // Contacts and top peers.
    .{ "Contact", "contacts" },             .{ "ImportedContact", "contacts" },
    .{ "ContactStatus", "contacts" },       .{ "SavedContact", "contacts" },
    .{ "ContactBirthday", "contacts" },     .{ "PopularContact", "contacts" },
    .{ "ExportedContactToken", "contacts" }, .{ "TopPeer", "contacts" },
    .{ "TopPeerCategory", "contacts" },     .{ "TopPeerCategoryPeers", "contacts" },
    .{ "InputContact", "contacts" },
    // Messages.
    .{ "Message", "messages" },             .{ "MessageAction", "messages" },
    .{ "MessageEntity", "messages" },       .{ "MessageMedia", "messages" },
    .{ "MessageRange", "messages" },        .{ "InputMessage", "messages" },
    .{ "InputReplyTo", "messages" },        .{ "InputMedia", "messages" },
    .{ "SendMessageAction", "messages" },   .{ "MessagesFilter", "messages" },
    .{ "MessageViews", "messages" },        .{ "MessageReplies", "messages" },
    .{ "MessageReactions", "messages" },    .{ "MessageReactor", "messages" },
    .{ "MessagePeerVote", "messages" },     .{ "MessagePeerReaction", "messages" },
    .{ "MessageExtendedMedia", "messages" }, .{ "MessageReplyHeader", "messages" },
    .{ "MessageFwdHeader", "messages" },    .{ "MessageReportOption", "messages" },
    .{ "PostInteractionCounters", "messages" }, .{ "SearchResultsCalendarPeriod", "messages" },
    .{ "SearchResultsPosition", "messages" }, .{ "SponsoredMessage", "messages" },
    .{ "Game", "messages" },                .{ "HighScore", "messages" },
    .{ "InputGame", "messages" },           .{ "InputSingleMedia", "messages" },
    .{ "TodoItem", "messages" },            .{ "TodoList", "messages" },
    .{ "TodoCompletion", "messages" },      .{ "SuggestedPost", "messages" },
    .{ "OutboxReadDate", "messages" },      .{ "RichMessage", "messages" },
    .{ "InputRichMessage", "messages" },    .{ "InputRichFile", "messages" },
    .{ "InputMessageReadMetric", "messages" }, .{ "SearchPostsFlood", "messages" },
    .{ "ExportedMessageLink", "messages" },
    // Updates.
    .{ "Update", "updates" },
    // Instant view / web previews.
    .{ "PageBlock", "pages" },              .{ "RichText", "pages" },
    .{ "Page", "pages" },                   .{ "PageTableCell", "pages" },
    .{ "PageTableRow", "pages" },           .{ "PageCaption", "pages" },
    .{ "PageRelatedArticle", "pages" },     .{ "PageListItem", "pages" },
    .{ "PageListOrderedItem", "pages" },    .{ "PageButton", "pages" },
    .{ "WebPage", "pages" },                .{ "WebPageAttribute", "pages" },
    // Privacy and notification settings.
    .{ "InputPrivacyKey", "privacy" },      .{ "PrivacyKey", "privacy" },
    .{ "InputPrivacyRule", "privacy" },     .{ "PrivacyRule", "privacy" },
    .{ "PeerNotifySettings", "privacy" },   .{ "InputPeerNotifySettings", "privacy" },
    .{ "PeerSettings", "privacy" },         .{ "GlobalPrivacySettings", "privacy" },
    .{ "ReactionsNotifySettings", "privacy" }, .{ "PaidReactionPrivacy", "privacy" },
    // Passport / secure identity + password KDF.
    .{ "SecureValueType", "secure" },       .{ "SecureValueError", "secure" },
    .{ "SecureFile", "secure" },            .{ "SecurePlainData", "secure" },
    .{ "SecureRequiredType", "secure" },    .{ "SecureData", "secure" },
    .{ "SecureValue", "secure" },           .{ "InputSecureValue", "secure" },
    .{ "SecureValueHash", "secure" },       .{ "SecureCredentialsEncrypted", "secure" },
    .{ "SecurePasswordKdfAlgo", "secure" }, .{ "PasswordKdfAlgo", "secure" },
    .{ "SecureSecretSettings", "secure" },  .{ "InputCheckPasswordSRP", "secure" },
    // Stickers, emoji and reactions.
    .{ "InputStickerSet", "stickers" },     .{ "StickerSet", "stickers" },
    .{ "StickerSetCovered", "stickers" },   .{ "StickerPack", "stickers" },
    .{ "StickerKeyword", "stickers" },      .{ "InputStickerSetItem", "stickers" },
    .{ "InputStickeredMedia", "stickers" }, .{ "EmojiGroup", "stickers" },
    .{ "EmojiList", "stickers" },           .{ "EmojiKeyword", "stickers" },
    .{ "EmojiKeywordsDifference", "stickers" }, .{ "EmojiURL", "stickers" },
    .{ "EmojiLanguage", "stickers" },       .{ "AvailableReaction", "stickers" },
    .{ "AvailableEffect", "stickers" },     .{ "ChatReactions", "stickers" },
    .{ "Reaction", "stickers" },            .{ "ReactionCount", "stickers" },
    .{ "ReactionNotificationsFrom", "stickers" }, .{ "SavedReactionTag", "stickers" },
    .{ "EmojiStatus", "stickers" },
    // Buttons and reply markups.
    .{ "InlineButtonType", "buttons" },     .{ "ButtonType", "buttons" },
    .{ "KeyboardButton", "buttons" },       .{ "KeyboardButtonRow", "buttons" },
    .{ "KeyboardButtonStyle", "buttons" },  .{ "KeyboardInlineButton", "buttons" },
    .{ "KeyboardInlineButtonRow", "buttons" }, .{ "ReplyMarkup", "buttons" },
    .{ "RichButtonStyle", "buttons" },
    // Bots and the inline platform.
    .{ "InputBotInlineMessage", "bots" },   .{ "BotInlineMessage", "bots" },
    .{ "InputBotInlineResult", "bots" },    .{ "BotInlineResult", "bots" },
    .{ "InputBotInlineMessageID", "bots" }, .{ "InlineQueryPeerType", "bots" },
    .{ "WebViewResult", "bots" },           .{ "WebViewMessageSent", "bots" },
    .{ "InlineBotWebView", "bots" },        .{ "InlineBotSwitchPM", "bots" },
    .{ "BotCommand", "bots" },              .{ "BotCommandScope", "bots" },
    .{ "BotInfo", "bots" },                 .{ "BotApp", "bots" },
    .{ "InputBotApp", "bots" },             .{ "BotPreviewMedia", "bots" },
    .{ "BotAppSettings", "bots" },          .{ "BotVerifierSettings", "bots" },
    .{ "BotVerification", "bots" },         .{ "ConnectedBot", "bots" },
    .{ "ConnectedBotStarRef", "bots" },     .{ "StarRefProgram", "bots" },
    .{ "AttachMenuPeerType", "bots" },      .{ "AttachMenuBotIconColor", "bots" },
    .{ "AttachMenuBotIcon", "bots" },       .{ "AttachMenuBot", "bots" },
    .{ "AttachMenuBots", "bots" },          .{ "AttachMenuBotsBot", "bots" },
    .{ "UrlAuthResult", "bots" },           .{ "JoinChatBotResult", "bots" },
    // Business hours / greeting / chat links.
    .{ "BusinessAwayMessageSchedule", "business" },  .{ "BusinessWeeklyOpen", "business" },
    .{ "BusinessWorkHours", "business" },   .{ "BusinessLocation", "business" },
    .{ "InputBusinessRecipients", "business" }, .{ "BusinessRecipients", "business" },
    .{ "InputBusinessGreetingMessage", "business" }, .{ "BusinessGreetingMessage", "business" },
    .{ "InputBusinessAwayMessage", "business" }, .{ "BusinessAwayMessage", "business" },
    .{ "InputBusinessIntro", "business" },  .{ "BusinessIntro", "business" },
    .{ "InputBusinessBotRecipients", "business" }, .{ "BusinessBotRecipients", "business" },
    .{ "InputBusinessChatLink", "business" }, .{ "BusinessChatLink", "business" },
    .{ "BusinessBotRights", "business" },   .{ "QuickReply", "business" },
    .{ "InputQuickReplyShortcut", "business" }, .{ "Timezone", "business" },
    .{ "Birthday", "business" },            .{ "BotBusinessConnection", "business" },
    .{ "PendingSuggestion", "business" },
    // Files, CDN and DC endpoints.
    .{ "InputFileLocation", "files" },      .{ "InputFile", "files" },
    .{ "InputEncryptedFile", "files" },     .{ "EncryptedFile", "files" },
    .{ "InputWebFileLocation", "files" },   .{ "FileHash", "files" },
    .{ "CdnPublicKey", "files" },           .{ "CdnConfig", "files" },
    .{ "DcOption", "files" },
    // Photos, documents and geo.
    .{ "Photo", "media" },                  .{ "VideoSize", "media" },
    .{ "GeoPoint", "media" },               .{ "GeoPointAddress", "media" },
    .{ "Document", "media" },               .{ "DocumentAttribute", "media" },
    .{ "MaskCoords", "media" },             .{ "MediaArea", "media" },
    .{ "MediaAreaCoordinates", "media" },   .{ "WebDocument", "media" },
    .{ "InputWebDocument", "media" },       .{ "InputPhoto", "media" },
    .{ "InputDocument", "media" },          .{ "InputGeoPoint", "media" },
    .{ "InputChatPhoto", "media" },         .{ "PhoneConnection", "media" },
    // Stars, gifts and auctions.
    .{ "StarGift", "stars" },               .{ "StarGiftAttribute", "stars" },
    .{ "StarGiftAttributeRarity", "stars" }, .{ "StarGiftAttributeId", "stars" },
    .{ "StarGiftAuctionState", "stars" },   .{ "StarGiftAuctionRound", "stars" },
    .{ "StarGiftAuctionUserState", "stars" }, .{ "StarGiftAuctionAcquiredGift", "stars" },
    .{ "StarGiftActiveAuctionState", "stars" }, .{ "StarGiftBackground", "stars" },
    .{ "StarGiftCollection", "stars" },     .{ "StarGiftUpgradePrice", "stars" },
    .{ "StarGiftAttributeCounter", "stars" }, .{ "SavedStarGift", "stars" },
    .{ "StarsAmount", "stars" },            .{ "StarsTransaction", "stars" },
    .{ "StarsTransactionPeer", "stars" },   .{ "StarsTopupOption", "stars" },
    .{ "StarsGiftOption", "stars" },        .{ "StarsRevenueStatus", "stars" },
    .{ "InputStarsTransaction", "stars" },  .{ "StarsSubscriptionPricing", "stars" },
    .{ "StarsSubscription", "stars" },      .{ "StarsRating", "stars" },
    .{ "StarsGiveawayOption", "stars" },    .{ "StarsGiveawayWinnersOption", "stars" },
    .{ "PrepaidGiveaway", "stars" },        .{ "AuctionBidLevel", "stars" },
    .{ "InputStarGiftAuction", "stars" },   .{ "DisallowedGiftsSettings", "stars" },
    // Calls and group calls.
    .{ "PhoneCall", "phone" },              .{ "PhoneCallDiscardReason", "phone" },
    .{ "InputPhoneCall", "phone" },         .{ "PhoneCallProtocol", "phone" },
    .{ "GroupCall", "phone" },              .{ "InputGroupCall", "phone" },
    .{ "GroupCallParticipant", "phone" },   .{ "GroupCallParticipantVideo", "phone" },
    .{ "GroupCallParticipantVideoSourceGroup", "phone" }, .{ "GroupCallMessage", "phone" },
    .{ "GroupCallDonor", "phone" },         .{ "GroupCallStreamChannel", "phone" },
    // Polls.
    .{ "Poll", "poll" },                    .{ "PollAnswer", "poll" },
    .{ "PollAnswerVoters", "poll" },        .{ "PollResults", "poll" },
    // Themes and wallpapers.
    .{ "Theme", "themes" },                 .{ "InputTheme", "themes" },
    .{ "InputThemeSettings", "themes" },    .{ "ThemeSettings", "themes" },
    .{ "BaseTheme", "themes" },             .{ "InputWallPaper", "themes" },
    .{ "WallPaper", "themes" },             .{ "WallPaperSettings", "themes" },
    .{ "InputChatTheme", "themes" },        .{ "ChatTheme", "themes" },
    // Statistics.
    .{ "StatsGraph", "stats" },             .{ "StatsDateRangeDays", "stats" },
    .{ "StatsAbsValueAndPrev", "stats" },   .{ "StatsPercentValue", "stats" },
    .{ "StatsGroupTopPoster", "stats" },    .{ "StatsGroupTopAdmin", "stats" },
    .{ "StatsGroupTopInviter", "stats" },   .{ "StatsURL", "stats" },
    .{ "PublicForward", "stats" },
    // Payments and invoicing.
    .{ "LabeledPrice", "payments" },        .{ "Invoice", "payments" },
    .{ "PaymentCharge", "payments" },       .{ "PostAddress", "payments" },
    .{ "PaymentRequestedInfo", "payments" }, .{ "PaymentSavedCredentials", "payments" },
    .{ "ShippingOption", "payments" },      .{ "InputPaymentCredentials", "payments" },
    .{ "InputInvoice", "payments" },        .{ "InputStorePaymentPurpose", "payments" },
    .{ "BankCardOpenUrl", "payments" },     .{ "PaymentFormMethod", "payments" },
    // Authorization and passkeys.
    .{ "Authorization", "auth" },           .{ "WebAuthorization", "auth" },
    .{ "EmailVerification", "auth" },       .{ "EmailVerifyPurpose", "auth" },
    .{ "Passkey", "auth" },                 .{ "InputPasskeyCredential", "auth" },
    .{ "InputPasskeyResponse", "auth" },
    // Account-level settings.
    .{ "AccountDaysTTL", "account" },       .{ "AutoDownloadSettings", "account" },
    .{ "AutoSaveSettings", "account" },     .{ "AutoSaveException", "account" },
    // Help / bootstrap.
    .{ "Config", "help" },                  .{ "NearestDc", "help" },
    .{ "RecentMeUrl", "help" },
    // Localization.
    .{ "LangPackString", "langpack" },      .{ "LangPackDifference", "langpack" },
    .{ "LangPackLanguage", "langpack" },
    // Premium and boosts.
    .{ "PremiumSubscriptionOption", "premium" }, .{ "PremiumGiftCodeOption", "premium" },
    .{ "Boost", "premium" },                .{ "MyBoost", "premium" },
    // Stories.
    .{ "StoryItem", "stories" },            .{ "StoryReaction", "stories" },
    .{ "StoryView", "stories" },            .{ "StoryViews", "stories" },
    .{ "StoryFwdHeader", "stories" },       .{ "StoryAlbum", "stories" },
    .{ "FoundStory", "stories" },           .{ "RecentStory", "stories" },
    .{ "PeerStories", "stories" },          .{ "StoriesStealthMode", "stories" },
    .{ "ExportedStoryLink", "stories" },
    // SMS jobs.
    .{ "SmsJob", "smsjobs" },
    // AI-assisted composing.
    .{ "InputAiComposeTone", "aicompose" }, .{ "AiComposeTone", "aicompose" },
    .{ "AiComposeToneExample", "aicompose" },
    // Communities.
    .{ "CommunityPeer", "communities" },    .{ "CommunityPeerRequest", "communities" },
    // Ephemeral media.
    .{ "EphemeralMessage", "ephemeral" },
    // Fragment collectibles.
    .{ "InputCollectible", "fragment" },
    // Everything else.
    .{ "ReportReason", "misc" },            .{ "ReportResult", "misc" },
    .{ "SponsoredMessageReportOption", "misc" }, .{ "SponsoredPeer", "misc" },
    .{ "WebDomainException", "misc" },      .{ "NotificationSound", "misc" },
});

/// Which types/<group>.zig a result type belongs to: full-name overrides
/// first, then the TL namespace, then — for root-namespace types — the
/// theme table, with `misc` as the catch-all. A constructor lands in the
/// group of its result type, so each types file is self-contained: its
/// unions and every constructor those unions dispatch to.
fn typeGroupName(result_type: []const u8) []const u8 {
    if (ns_group_override.get(result_type)) |group| return group;
    const ns = naming.namespaceOf(result_type);
    if (ns.len > 0) return ns;
    return root_type_theme.get(naming.lastSegment(result_type)) orelse "misc";
}

/// Declarations that never produce emitted code: generic combinators
/// (`vector`, the `invokeWith*` wrappers) and the core schema's bare
/// primitive placeholders (`int ? = Int;`).
fn skipDecl(c: *const ast.Constructor) bool {
    return c.core_bare or naming.isGeneric(c);
}

pub const Emitter = struct {
    allocator: std.mem.Allocator, // arena for temporary strings
    out: std.ArrayList(u8) = .empty,
    opts: Options,
    schema: *const Schema,
    tmp_counter: usize = 0,
    /// Final Zig path for each emitted constructor (TL name → escaped
    /// path). Filled during `emit` after namespace collection; resolves
    /// collisions such as the top-level `updates` constructor vs the
    /// `updates` namespace (constructor is renamed to `updates_`).
    ctor_paths: std.StringHashMap([]const u8) = undefined,
    /// Final Zig path for each emitted result-type union (TL type name →
    /// path). A namespaced union whose short name collides with a root
    /// union (`messages.ChatFull` vs root `ChatFull`) is suffixed with `_`
    /// so bare references stay unambiguous.
    type_paths: std.StringHashMap([]const u8) = undefined,
    /// Split mode: file-local declaration identifier for every emitted
    /// declaration (TL full name → ident), filled by `assignDeclNames`.
    /// Empty in single-file mode, where namespace containers keep decls
    /// in separate scopes and last segments never collide.
    decl_names: std.StringHashMap([]const u8) = undefined,
    /// Result types that participate in a reference cycle (TL allows
    /// recursive types such as InputPeer). Their fields use `*T` pointers
    /// and are heap-allocated during deserialization.
    cycle_types: std.StringHashMap(void) = undefined,
    /// Namespace buckets in first-seen order; filled by `prepare`.
    order: std.ArrayList(NamespaceEntry) = .empty,
    /// Completed output files in split mode.
    files: std.ArrayList(OutputFile) = .empty,
    /// Namespace of the file currently being emitted (null = single-file
    /// mode, where every reference stays fully qualified). In split mode
    /// any non-null value routes references through the entry module.
    cur_ns: ?[]const u8 = null,

    fn line(self: *Emitter, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.allocPrint(self.allocator, fmt ++ "\n", args) catch unreachable; // arena OOM is fatal for codegen
        self.out.appendSlice(self.allocator, s) catch unreachable;
    }

    fn raw(self: *Emitter, s: []const u8) void {
        self.out.appendSlice(self.allocator, s) catch unreachable;
    }

    fn fresh(self: *Emitter, comptime prefix: []const u8) []const u8 {
        self.tmp_counter += 1;
        return std.fmt.allocPrint(self.allocator, prefix ++ "{d}", .{self.tmp_counter}) catch unreachable;
    }

    pub fn emit(self: *Emitter) std.mem.Allocator.Error![]const u8 {
        try self.prepare();
        try self.emitHeader();

        for (self.order.items) |entry| {
            const ns = try naming.ident(self.allocator, entry.ns);
            const group = &entry.group;
            if (ns.len == 0) {
                for (group.constructors.items) |c| try self.emitStruct(c, false);
                for (group.functions.items) |c| try self.emitStruct(c, true);
                for (group.unions.items) |t| try self.emitUnion(t);
            } else {
                self.line("pub const {s} = struct {{", .{ns});
                for (group.constructors.items) |c| try self.emitStruct(c, false);
                for (group.functions.items) |c| try self.emitStruct(c, true);
                for (group.unions.items) |t| try self.emitUnion(t);
                self.line("}};", .{});
            }
        }
        if (self.opts.self_test) self.emitSelfTest();
        return self.out.items;
    }

    /// Split-mode entry point: emits the tree layout — the entry module
    /// (`opts.root_name`, default `mod.zig`) re-exporting every
    /// declaration, `types/` (result-type unions with their constructors,
    /// grouped by TL namespace and, at the root, thematically),
    /// `functions/` (one file per namespace), and `registry.zig`. File
    /// names are relative to the output root. The `td.api` surface is
    /// unchanged: every declaration resolves exactly as it did in
    /// single-file mode.
    pub fn emitSplit(self: *Emitter) std.mem.Allocator.Error![]OutputFile {
        try self.prepare();

        // Tree bucketing: types (constructors + result-type unions) by
        // group, functions by TL namespace. First-seen order keeps the
        // output deterministic.
        var type_index = std.StringHashMap(usize).init(self.allocator);
        var fn_index = std.StringHashMap(usize).init(self.allocator);
        var type_groups: std.ArrayList(TypeGroup) = .empty;
        var fn_groups: std.ArrayList(FnGroup) = .empty;
        var ns_order: std.ArrayList([]const u8) = .empty;
        var ns_seen = std.StringHashMap(void).init(self.allocator);

        for (self.schema.constructors) |*c| {
            if (skipDecl(c)) continue;
            const g = try self.typeGroupFor(&type_index, &type_groups, c.result_type.name);
            try g.ctors.append(self.allocator, c);
            try self.noteNamespace(&ns_order, &ns_seen, c.name);
        }
        var seen_unions = std.StringHashMap(void).init(self.allocator);
        for (self.schema.constructors) |*c| {
            if (skipDecl(c)) continue;
            if (naming.isTypeVarRef(&c.result_type)) continue;
            const gop = try seen_unions.getOrPut(c.result_type.name);
            if (gop.found_existing) continue;
            const g = try self.typeGroupFor(&type_index, &type_groups, c.result_type.name);
            try g.unions.append(self.allocator, c.result_type.name);
        }
        for (self.schema.functions) |*f| {
            if (skipDecl(f)) continue;
            const g = try self.fnGroupFor(&fn_index, &fn_groups, f.name);
            try g.fns.append(self.allocator, f);
            try self.noteNamespace(&ns_order, &ns_seen, f.name);
        }

        // Group files are flat: a group's constructors and unions share one
        // file scope, so last-segment collisions (`photo` vs `media.photo`
        // in the same themed file) need deterministic decl renames.
        // Pre-computed before any emission — the entry module's re-exports
        // reference these names.
        try self.assignDeclNames(type_groups.items, fn_groups.items);

        // Entry module: registry + index imports + flat re-exports.
        try self.emitEntryModule(type_groups.items, fn_groups.items, ns_order.items);
        try self.pushFile(self.opts.root_name);

        // types/: an index module, then one file per group — constructors
        // first, then the result-type unions dispatching to them.
        if (type_groups.items.len > 0) {
            self.emitGeneratedBanner();
            for (type_groups.items) |*g| {
                self.line("pub const {s} = @import(\"{s}\");", .{
                    try naming.ident(self.allocator, g.name),
                    try self.typeIndexImport(g.name),
                });
            }
            try self.pushFile("types/mod.zig");
            for (type_groups.items) |*g| {
                self.cur_ns = g.name;
                defer self.cur_ns = null;
                try self.emitContentHeader();
                for (g.ctors.items) |c| try self.emitStruct(c, false);
                for (g.unions.items) |t| try self.emitUnion(t);
                try self.pushFile(try self.typeFileName(g.name));
            }
        }

        // functions/: an index module, then one request-struct file per
        // namespace.
        if (fn_groups.items.len > 0) {
            self.emitGeneratedBanner();
            for (fn_groups.items) |*g| {
                self.line("pub const {s} = @import(\"{s}\");", .{
                    try naming.ident(self.allocator, if (g.ns.len == 0) "root" else g.ns),
                    try self.functionIndexImport(g.ns),
                });
            }
            try self.pushFile("functions/mod.zig");
            for (fn_groups.items) |*g| {
                self.cur_ns = g.ns;
                defer self.cur_ns = null;
                try self.emitContentHeader();
                for (g.fns.items) |f| try self.emitStruct(f, true);
                try self.pushFile(try self.functionFileName(g.ns));
            }
        }

        try self.emitRegistry();
        try self.pushFile("registry.zig");

        return self.files.items;
    }

    /// The entry module (`mod.zig`): the registry and index imports plus
    /// a re-export of every declaration — root declarations flat at the
    /// top level, namespaced ones inside a container struct per namespace
    /// — so `td.api.<path>` resolves exactly as it did in single-file
    /// mode. Re-exports only; no declaration bodies live here.
    fn emitEntryModule(
        self: *Emitter,
        type_groups: []const TypeGroup,
        fn_groups: []const FnGroup,
        ns_order: []const []const u8,
    ) std.mem.Allocator.Error!void {
        self.line("//! GENERATED by td TL code generator from \"{s}\".", .{self.opts.source_name});
        self.line("//! Do not edit by hand; regenerate with td-gen.", .{});
        self.raw(
            \\//!
            \\//! Entry module of the split generated API. Every declaration is
            \\//! re-exported here with the same flat surface as the single-file
            \\//! layout; the bodies live in the types/ and functions/ subtrees.
            \\
            \\
        );
        self.line("pub const registry = @import(\"registry.zig\");", .{});
        self.line("pub const types = @import(\"types/mod.zig\");", .{});
        if (fn_groups.len > 0) self.line("pub const functions = @import(\"functions/mod.zig\");", .{});
        self.emitLayerConst();

        self.raw("\n// Root namespace, re-exported flat:\n");
        for (type_groups) |*g| {
            const file = try self.typeFileName(g.name);
            for (g.ctors.items) |c| {
                if (naming.namespaceOf(c.name).len != 0) continue;
                const short = naming.lastSegment(self.ctor_paths.get(c.name) orelse c.name);
                self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(c.name) orelse short });
            }
            for (g.unions.items) |t| {
                if (naming.namespaceOf(t).len != 0) continue;
                const short = naming.lastSegment(self.type_paths.get(t) orelse t);
                self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(t) orelse short });
            }
        }
        for (fn_groups) |*g| {
            if (g.ns.len != 0) continue;
            const file = try self.functionFileName(g.ns);
            for (g.fns.items) |f| {
                const short = naming.lastSegment(self.ctor_paths.get(f.name) orelse f.name);
                self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(f.name) orelse short });
            }
        }

        self.raw("\n// Namespaced declarations:\n");
        for (ns_order) |ns| {
            if (ns.len == 0) continue;
            self.line("\npub const {s} = struct {{", .{try naming.ident(self.allocator, ns)});
            for (type_groups) |*g| {
                const file = try self.typeFileName(g.name);
                for (g.ctors.items) |c| {
                    if (!std.mem.eql(u8, naming.namespaceOf(c.name), ns)) continue;
                    const short = naming.lastSegment(self.ctor_paths.get(c.name) orelse c.name);
                    self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(c.name) orelse short });
                }
            }
            for (fn_groups) |*g| {
                if (!std.mem.eql(u8, g.ns, ns)) continue;
                const file = try self.functionFileName(g.ns);
                for (g.fns.items) |f| {
                    const short = naming.lastSegment(self.ctor_paths.get(f.name) orelse f.name);
                    self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(f.name) orelse short });
                }
            }
            for (type_groups) |*g| {
                const file = try self.typeFileName(g.name);
                for (g.unions.items) |t| {
                    if (!std.mem.eql(u8, naming.namespaceOf(t), ns)) continue;
                    const short = naming.lastSegment(self.type_paths.get(t) orelse t);
                    self.line("pub const {s} = @import(\"{s}\").{s};", .{ short, file, self.decl_names.get(t) orelse short });
                }
            }
            self.line("}};", .{});
        }

        if (self.opts.self_test) self.emitSelfTest();
    }

    /// The GENERATED banner for modules without imports (the types/ and
    /// functions/ index modules).
    fn emitGeneratedBanner(self: *Emitter) void {
        self.line("//! GENERATED by td TL code generator from \"{s}\".", .{self.opts.source_name});
        self.line("//! Do not edit by hand; regenerate with td-gen.", .{});
        self.raw("\n");
    }

    /// Header for a split content file under types/ or functions/: the
    /// usual preamble, with the td import depth-adjusted for the
    /// subdirectory, plus the entry module imported as `api` for
    /// cross-file references.
    fn emitContentHeader(self: *Emitter) std.mem.Allocator.Error!void {
        self.emitGeneratedBanner();
        self.raw("const std = @import(\"std\");\n");
        self.line("const td = @import(\"{s}\");", .{try self.contentModuleImport()});
        self.raw("const Writer = td.tl.Writer;\nconst Reader = td.tl.Reader;\nconst TlError = td.TlError;\n");
        self.raw("const vector_constructor_id = td.tl.vector_constructor_id;\n");
        self.line("\nconst api = @import(\"{s}\");", .{try self.hubImport()});
        self.raw("\n");
    }

    /// File name (relative to the output root) of a types group.
    fn typeFileName(self: *Emitter, group: []const u8) std.mem.Allocator.Error![]const u8 {
        const id = try naming.ident(self.allocator, group);
        return std.fmt.allocPrint(self.allocator, "types/{s}.zig", .{id});
    }

    /// File name (relative to the output root) of a functions namespace
    /// (the root namespace writes `functions/root.zig`).
    fn functionFileName(self: *Emitter, ns: []const u8) std.mem.Allocator.Error![]const u8 {
        const id = if (ns.len == 0) "root" else try naming.ident(self.allocator, ns);
        return std.fmt.allocPrint(self.allocator, "functions/{s}.zig", .{id});
    }

    /// Import path from a types//functions/ content file back to the
    /// entry module at the output root.
    fn hubImport(self: *Emitter) std.mem.Allocator.Error![]const u8 {
        return std.fmt.allocPrint(self.allocator, "../{s}", .{self.opts.root_name});
    }

    /// Import path for the td module from a content file: module names are
    /// depth-independent, but relative file paths (`--module ../root.zig`)
    /// sit one directory deeper than the entry module.
    fn contentModuleImport(self: *Emitter) std.mem.Allocator.Error![]const u8 {
        if (self.opts.module_name.len > 0 and self.opts.module_name[0] == '.') {
            return std.fmt.allocPrint(self.allocator, "../{s}", .{self.opts.module_name});
        }
        return self.opts.module_name;
    }

    /// File name imported by the types/ index module: a sibling in the
    /// same directory, so just `<group>.zig`.
    fn typeIndexImport(self: *Emitter, group: []const u8) std.mem.Allocator.Error![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{s}.zig", .{try naming.ident(self.allocator, group)});
    }

    /// File name imported by the functions/ index module (the root
    /// namespace writes `functions/root.zig`).
    fn functionIndexImport(self: *Emitter, ns: []const u8) std.mem.Allocator.Error![]const u8 {
        const id = if (ns.len == 0) "root" else try naming.ident(self.allocator, ns);
        return std.fmt.allocPrint(self.allocator, "{s}.zig", .{id});
    }

    /// Split mode only: fills `decl_names` — the file-local declaration
    /// identifier for every emitted declaration. A themed group file mixes
    /// root and namespaced declarations whose last segments can collide
    /// (`photo` vs `media.photo`, `userFull` vs `user.userFull`); the
    /// first-seen declaration keeps its name and later ones get a `_`
    /// suffix. Deterministic: assignment follows the same first-seen
    /// iteration as emission. References never spell these names directly —
    /// every cross-file reference routes through the entry module, whose
    /// re-exports keep the original surface name and alias the renamed
    /// declaration.
    fn assignDeclNames(self: *Emitter, type_groups: []const TypeGroup, fn_groups: []const FnGroup) std.mem.Allocator.Error!void {
        for (type_groups) |*g| {
            var taken = std.StringHashMap(void).init(self.allocator);
            defer taken.deinit();
            for (g.ctors.items) |c|
                try self.takeDeclName(&taken, self.ctor_paths.get(c.name) orelse c.name, c.name);
            for (g.unions.items) |t|
                try self.takeDeclName(&taken, self.type_paths.get(t) orelse t, t);
        }
        for (fn_groups) |*g| {
            var taken = std.StringHashMap(void).init(self.allocator);
            defer taken.deinit();
            for (g.fns.items) |f|
                try self.takeDeclName(&taken, self.ctor_paths.get(f.name) orelse f.name, f.name);
        }
    }

    /// Records the file-local decl name for `full_name`: the last segment
    /// of `path`, `_`-suffixed until unique within the file.
    fn takeDeclName(self: *Emitter, taken: *std.StringHashMap(void), path: []const u8, full_name: []const u8) std.mem.Allocator.Error!void {
        var name = naming.lastSegment(path);
        while (taken.contains(name)) {
            name = try std.fmt.allocPrint(self.allocator, "{s}_", .{name});
        }
        try taken.put(name, {});
        try self.decl_names.put(full_name, name);
    }

    fn pushFile(self: *Emitter, name: []const u8) std.mem.Allocator.Error!void {
        try self.files.append(self.allocator, .{ .name = name, .src = self.out.items });
        self.out = .empty;
    }

    /// Groups declarations into namespace buckets (first-seen order so
    /// output is deterministic), computes constructor/union Zig paths with
    /// collision renames, and detects recursive result types. Shared by
    /// `emit` and `emitSplit`.
    fn prepare(self: *Emitter) std.mem.Allocator.Error!void {
        var index = std.StringHashMap(usize).init(self.allocator);
        for (self.schema.constructors) |*c| {
            if (skipDecl(c)) continue;
            try (try self.groupFor(&index, c.name)).constructors.append(self.allocator, c);
        }
        for (self.schema.functions) |*f| {
            if (skipDecl(f)) continue;
            try (try self.groupFor(&index, f.name)).functions.append(self.allocator, f);
        }
        // Result-type unions, bucketed by the result type's namespace.
        var seen_types = std.StringHashMap(void).init(self.allocator);
        for (self.schema.constructors) |*c| {
            if (skipDecl(c)) continue;
            if (naming.isTypeVarRef(&c.result_type)) continue;
            const gop = try seen_types.getOrPut(c.result_type.name);
            if (gop.found_existing) continue;
            try (try self.groupFor(&index, c.result_type.name)).unions.append(self.allocator, c.result_type.name);
        }

        // Compute final Zig paths for every emitted constructor, applying
        // keyword escaping and namespace-collision renames up front so all
        // references agree.
        self.ctor_paths = std.StringHashMap([]const u8).init(self.allocator);
        self.decl_names = std.StringHashMap([]const u8).init(self.allocator);
        var ns_set = std.StringHashMap(void).init(self.allocator);
        for (self.order.items) |entry| {
            if (entry.ns.len > 0) try ns_set.put(entry.ns, {});
        }
        for ([_][]const ast.Constructor{ self.schema.constructors, self.schema.functions }) |decls| {
            for (decls) |*c| {
                if (skipDecl(c)) continue;
                try self.ctor_paths.put(c.name, try self.computeCtorPath(c.name, &ns_set));
            }
        }

        // Compute final Zig paths for result-type unions, renaming
        // namespaced unions whose short name collides with a root union.
        self.type_paths = std.StringHashMap([]const u8).init(self.allocator);
        var root_shorts = std.StringHashMap(void).init(self.allocator);
        var it_types = seen_types.keyIterator();
        while (it_types.next()) |t| {
            if (naming.namespaceOf(t.*).len == 0) try root_shorts.put(naming.lastSegment(t.*), {});
        }
        var it_types2 = seen_types.keyIterator();
        while (it_types2.next()) |t| {
            try self.type_paths.put(t.*, try self.computeTypePath(t.*, &root_shorts));
        }

        // Detect reference cycles between result types: a type is "cyclic"
        // when it can reach itself through named-type fields of its
        // constructors (possibly through vectors). Cyclic types need
        // pointer fields; everything else stays by-value.
        self.cycle_types = std.StringHashMap(void).init(self.allocator);
        var edges = std.StringHashMap(std.ArrayList([]const u8)).init(self.allocator);
        var it_t = seen_types.keyIterator();
        while (it_t.next()) |t| {
            const list = try edges.getOrPut(t.*);
            if (!list.found_existing) list.value_ptr.* = .empty;
            for (self.schema.constructors) |*c| {
                if (skipDecl(c)) continue;
                if (!std.mem.eql(u8, c.result_type.name, t.*)) continue;
                for (c.params) |p| {
                    try self.appendNamedDeps(&p.type_expr, &seen_types, list.value_ptr);
                }
            }
        }
        var it_src = seen_types.keyIterator();
        while (it_src.next()) |src| {
            var visited = std.StringHashMap(void).init(self.allocator);
            if (try self.reaches(&visited, edges, src.*, src.*)) {
                try self.cycle_types.put(src.*, {});
            }
        }
    }

    fn emitSelfTest(self: *Emitter) void {
        self.raw(
            \\test {
            \\    @setEvalBranchQuota(10_000_000);
            \\    refAllDeclsRecursive(@This());
            \\}
            \\
        );
        self.raw(
            \\
            \\fn refAllDeclsRecursive(comptime T: type) void {
            \\    inline for (comptime @import("std").meta.declarations(T)) |decl| {
            \\        if (@TypeOf(@field(T, decl.name)) == type) {
            \\            switch (@typeInfo(@field(T, decl.name))) {
            \\                .@"struct", .@"enum", .@"union", .@"opaque" => refAllDeclsRecursive(@field(T, decl.name)),
            \\                else => {},
            \\            }
            \\        }
            \\        _ = &@field(T, decl.name);
            \\    }
            \\}
            \\
        );
    }

    const NamespaceGroup = struct {
        constructors: std.ArrayList(*const ast.Constructor) = .empty,
        functions: std.ArrayList(*const ast.Constructor) = .empty,
        unions: std.ArrayList([]const u8) = .empty, // result type full names
    };

    const NamespaceEntry = struct { ns: []const u8, group: NamespaceGroup };

    /// A types/ file bucket: the constructors of the group's result types
    /// plus the result-type unions themselves.
    const TypeGroup = struct {
        name: []const u8, // file base name (TL namespace or theme)
        ctors: std.ArrayList(*const ast.Constructor) = .empty,
        unions: std.ArrayList([]const u8) = .empty, // result type full names
    };

    /// A functions/ file bucket: one TL namespace's request structs.
    const FnGroup = struct {
        ns: []const u8, // TL namespace ("" = root)
        fns: std.ArrayList(*const ast.Constructor) = .empty,
    };

    /// Finds or creates the types group for `result_type`, preserving
    /// first-seen order (indexed by group name in `index`).
    fn typeGroupFor(
        self: *Emitter,
        index: *std.StringHashMap(usize),
        groups: *std.ArrayList(TypeGroup),
        result_type: []const u8,
    ) std.mem.Allocator.Error!*TypeGroup {
        const name = typeGroupName(result_type);
        const gop = try index.getOrPut(name);
        if (!gop.found_existing) {
            gop.value_ptr.* = groups.items.len;
            try groups.append(self.allocator, .{ .name = name });
        }
        return &groups.items[gop.value_ptr.*];
    }

    /// Finds or creates the functions group for `name`'s namespace,
    /// preserving first-seen order.
    fn fnGroupFor(
        self: *Emitter,
        index: *std.StringHashMap(usize),
        groups: *std.ArrayList(FnGroup),
        name: []const u8,
    ) std.mem.Allocator.Error!*FnGroup {
        const ns = naming.namespaceOf(name);
        const gop = try index.getOrPut(ns);
        if (!gop.found_existing) {
            gop.value_ptr.* = groups.items.len;
            try groups.append(self.allocator, .{ .ns = ns });
        }
        return &groups.items[gop.value_ptr.*];
    }

    /// Records `tl_name`'s namespace in first-seen order.
    fn noteNamespace(
        self: *Emitter,
        order: *std.ArrayList([]const u8),
        seen: *std.StringHashMap(void),
        tl_name: []const u8,
    ) std.mem.Allocator.Error!void {
        const ns = naming.namespaceOf(tl_name);
        const gop = try seen.getOrPut(ns);
        if (!gop.found_existing) try order.append(self.allocator, ns);
    }

    /// Finds or creates the namespace bucket for `name`, preserving
    /// first-seen order in `self.order` (indexed by `index`).
    fn groupFor(
        self: *Emitter,
        index: *std.StringHashMap(usize),
        name: []const u8,
    ) std.mem.Allocator.Error!*NamespaceGroup {
        const ns = naming.namespaceOf(name);
        const gop = try index.getOrPut(ns);
        if (!gop.found_existing) {
            gop.value_ptr.* = self.order.items.len;
            try self.order.append(self.allocator, .{ .ns = ns, .group = .{} });
        }
        return &self.order.items[gop.value_ptr.*].group;
    }

    fn emitHeader(self: *Emitter) std.mem.Allocator.Error!void {
        self.line("//! GENERATED by td TL code generator from \"{s}\".", .{self.opts.source_name});
        self.line("//! Do not edit by hand; regenerate with td-gen.", .{});
        self.raw("\nconst std = @import(\"std\");\n");
        self.line("const td = @import(\"{s}\");", .{self.opts.module_name});
        self.raw("const Writer = td.tl.Writer;\nconst Reader = td.tl.Reader;\nconst TlError = td.TlError;\n");
        self.raw("const vector_constructor_id = td.tl.vector_constructor_id;\n");
        self.emitLayerConst();
        self.raw("\n");
    }

    /// The schema's layer as a global constant of the generated module
    /// (present exactly when the schema carried a `// LAYER <n>`
    /// comment). The RPC layer sends it in `invokeWithLayer`, so a
    /// regeneration updates it everywhere at once.
    fn emitLayerConst(self: *Emitter) void {
        const n = self.schema.layer orelse return;
        self.line("\n/// Schema layer this API was generated from (`// LAYER {d}` in the schema).", .{n});
        self.line("pub const layer: i32 = {d};", .{n});
    }

    fn wireParams(self: *Emitter, c: *const ast.Constructor) std.mem.Allocator.Error![]const *const ast.Param {
        // params in wire order, excluding generic bindings
        var list: std.ArrayList(*const ast.Param) = .empty;
        for (c.params) |*p| {
            if (p.is_type_var or p.iterative) continue;
            try list.append(self.allocator, p);
        }
        return list.items;
    }

    /// How many optional fields reference each natural flags field.
    fn flagsRefCount(params: []const *const ast.Param, flags_name: []const u8) usize {
        var n: usize = 0;
        for (params) |p| {
            if (p.flag_index != null and p.flags_field != null and
                std.mem.eql(u8, p.flags_field.?, flags_name)) n += 1;
        }
        return n;
    }

    fn emitStruct(self: *Emitter, c: *const ast.Constructor, is_function: bool) std.mem.Allocator.Error!void {
        const path = try self.qualifiedCtorPath(c.name);
        const sname = self.decl_names.get(c.name) orelse naming.lastSegment(path);
        const params = try self.wireParams(c);

        self.line("pub const {s} = struct {{", .{sname});
        self.line("    pub const constructor_id: u32 = 0x{x:0>8};", .{c.id});
        // Functions link to their result type so the RPC layer can offer a
        // typed `invoke` without a hand-written mapping. Skipped for result
        // types the schema never emits a union for (none in practice —
        // validation requires every function result type to have
        // constructors).
        if (is_function and self.resultEmittable(&c.result_type)) {
            self.line("    pub const Result = {s};", .{self.resultTypeMapped(&c.result_type)});
        }

        for (params) |p| {
            if (std.mem.eql(u8, p.type_expr.name, "#")) continue; // natural flags field: computed
            const fname = try naming.ident(self.allocator, p.name);
            if (p.flag_index != null) {
                if (std.mem.eql(u8, p.type_expr.name, "true")) {
                    self.line("    {s}: bool = false,", .{fname});
                } else {
                    self.line("    {s}: ?{s} = null,", .{ fname, self.zigTypeMapped(&p.type_expr) });
                }
            } else {
                self.line("    {s}: {s},", .{ fname, self.zigTypeMapped(&p.type_expr) });
            }
        }

        self.emitSerialize(params, is_function);
        if (!is_function) self.emitDeserialize(params);
        self.line("}};", .{});
        self.raw("\n");
    }

    fn emitSerialize(self: *Emitter, params: []const *const ast.Param, is_function: bool) void {
        // `@This()` avoids ambiguity when a constructor's short name clashes
        // with its namespace or a sibling declaration (e.g. contacts.contacts).
        self.raw("\n    pub fn serialize(self: *const @This(), w: *Writer) TlError!void {\n");
        var uses_w = is_function;
        var uses_self = false;
        if (is_function) {
            self.line("        try w.writeConstructorId(constructor_id);", .{});
        }

        // Pre-pass: compute every natural flags word from its optionals so
        // the value is ready wherever the flags word sits in wire order.
        for (params) |p| {
            if (!std.mem.eql(u8, p.type_expr.name, "#")) continue;
            const refs = flagsRefCount(params, p.name);
            self.line("        {s} {s}: u32 = 0;", .{ if (refs > 0) "var" else "const", p.name });
            for (params) |q| {
                if (q.flag_index == null) continue;
                if (!std.mem.eql(u8, q.flags_field.?, p.name)) continue;
                const f = naming.ident(self.allocator, q.name) catch unreachable;
                if (std.mem.eql(u8, q.type_expr.name, "true")) {
                    self.line("        if (self.{s}) {s} |= 1 << {d};", .{ f, p.name, q.flag_index.? });
                } else {
                    self.line("        if (self.{s} != null) {s} |= 1 << {d};", .{ f, p.name, q.flag_index.? });
                }
                uses_self = true;
            }
            uses_w = true;
        }

        for (params) |p| {
            const fname = naming.ident(self.allocator, p.name) catch unreachable;
            if (std.mem.eql(u8, p.type_expr.name, "#")) {
                self.line("        try w.writeUInt({s});", .{p.name});
            } else if (p.flag_index != null) {
                if (std.mem.eql(u8, p.type_expr.name, "true")) continue;
                self.line("        if (self.{s}) |v| {{", .{fname});
                self.emitWriteValue(&p.type_expr, "v", 2);
                self.raw("        }\n");
                uses_self = true;
                uses_w = true;
            } else {
                self.emitWriteValue(&p.type_expr, std.fmt.allocPrint(self.allocator, "self.{s}", .{fname}) catch unreachable, 1);
                uses_self = true;
                uses_w = true;
            }
        }
        if (!uses_self) self.raw("        _ = self;\n");
        if (!uses_w) self.raw("        _ = w;\n");
        self.raw("    }\n");
    }

    fn emitDeserialize(self: *Emitter, params: []const *const ast.Param) void {
        self.raw("\n    pub fn deserialize(allocator: std.mem.Allocator, r: *Reader) TlError!@This() {\n");

        if (params.len == 0) {
            self.raw("        _ = allocator;\n        _ = r;\n        return .{};\n    }\n");
            return;
        }

        self.raw("        var self: @This() = undefined;\n");

        var uses_allocator = false;
        for (params) |p| {
            const fname = naming.ident(self.allocator, p.name) catch unreachable;
            if (std.mem.eql(u8, p.type_expr.name, "#")) {
                self.line("        const {s} = try r.readUInt();", .{p.name});
                if (flagsRefCount(params, p.name) == 0) {
                    self.line("        _ = {s};", .{p.name});
                }
            } else if (p.flag_index != null) {
                if (std.mem.eql(u8, p.type_expr.name, "true")) {
                    self.line("        self.{s} = ({s} >> {d}) & 1 != 0;", .{ fname, p.flags_field.?, p.flag_index.? });
                } else {
                    self.line("        if (({s} >> {d}) & 1 != 0) {{", .{ p.flags_field.?, p.flag_index.? });
                    uses_allocator = self.emitReadValue(&p.type_expr, std.fmt.allocPrint(self.allocator, "self.{s}", .{fname}) catch unreachable, 2) or uses_allocator;
                    self.raw("        } else {\n            self.");
                    self.raw(fname);
                    self.raw(" = null;\n        }\n");
                }
            } else {
                uses_allocator = self.emitReadValue(&p.type_expr, std.fmt.allocPrint(self.allocator, "self.{s}", .{fname}) catch unreachable, 1) or uses_allocator;
            }
        }
        if (!uses_allocator) self.raw("        _ = allocator;\n");
        self.raw("        return self;\n    }\n");
    }

    fn indentTo(self: *Emitter, extra: usize) void {
        const spaces = "                                "; // 32 spaces = 8 levels
        self.raw(spaces[0 .. @min(4 * (extra + 1), spaces.len)]);
    }

    /// Emits statements writing `access` (a value of the type described by
    /// `expr`) to `w`, at the given extra indentation level.
    fn emitWriteValue(self: *Emitter, expr: *const ast.TypeExpr, access: []const u8, extra: usize) void {
        if (naming.isVector(expr)) {
            const elem = self.fresh("elem_");
            self.indentTo(extra);
            if (!naming.isBareVector(expr)) {
                self.line("try w.writeUInt(vector_constructor_id);", .{});
            }
            self.indentTo(extra);
            self.line("try w.writeVectorLength({s}.len);", .{access});
            self.indentTo(extra);
            self.line("for ({s}) |{s}| {{", .{ access, elem });
            self.emitWriteValue(self.boxedElemExpr(expr.arg.?, naming.isBareVector(expr)), elem, extra + 1);
            self.indentTo(extra);
            self.raw("}\n");
            return;
        }
        self.indentTo(extra);
        if (naming.isTypeVarRef(expr)) {
            self.line("try w.writeBytes({s});", .{access});
        } else if (naming.scalarZigType(expr.name)) |s| {
            if (std.mem.eql(u8, s, "bool")) {
                self.line("try w.writeBool({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "string")) {
                self.line("try w.writeString({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "bytes")) {
                self.line("try w.writeBytes({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "int")) {
                self.line("try w.writeInt({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "long")) {
                self.line("try w.writeLong({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "double")) {
                self.line("try w.writeDouble({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "int128")) {
                self.line("try w.writeInt128({s});", .{access});
            } else if (std.mem.eql(u8, expr.name, "int256")) {
                self.line("try w.writeInt256({s});", .{access});
            } else {
                unreachable;
            }
        } else {
            self.line("try {s}.serialize(w);", .{access});
        }
    }

    /// Emits statements reading a value of the type described by `expr`
    /// from `r` into `dest`, at the given extra indentation level.
    /// Returns true when the emitted code uses `allocator` (vectors and
    /// nested combinator types do; borrowed scalars do not).
    fn emitReadValue(self: *Emitter, expr: *const ast.TypeExpr, dest: []const u8, extra: usize) bool {
        if (naming.isVector(expr)) {
            const len = self.fresh("len_");
            const vec = self.fresh("vec_");
            const elem = self.fresh("elem_");
            const bare = naming.isBareVector(expr);
            const elem_expr = self.boxedElemExpr(expr.arg.?, bare);
            const elem_ty = self.zigTypeMapped(elem_expr);
            self.indentTo(extra);
            if (!bare) {
                self.line("if ((try r.readUInt()) != vector_constructor_id) return error.InvalidValue;", .{});
            }
            self.indentTo(extra);
            self.line("const {s} = try r.readVectorLength();", .{len});
            self.indentTo(extra);
            self.line("const {s} = allocator.alloc({s}, {s}) catch return error.OutOfMemory;", .{ vec, elem_ty, len });
            self.indentTo(extra);
            self.line("for ({s}) |*{s}| {{", .{ vec, elem });
            _ = self.emitReadValue(elem_expr, std.fmt.allocPrint(self.allocator, "{s}.*", .{elem}) catch unreachable, extra + 1);
            self.indentTo(extra);
            self.raw("}\n");
            self.indentTo(extra);
            self.line("{s} = {s};", .{ dest, vec });
            return true;
        }
        self.indentTo(extra);
        if (naming.isTypeVarRef(expr)) {
            self.line("{s} = try r.readBytes();", .{dest});
            return false;
        } else if (naming.scalarZigType(expr.name)) |s| {
            if (std.mem.eql(u8, s, "bool")) {
                self.line("{s} = try r.readBool();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "string")) {
                self.line("{s} = try r.readString();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "bytes")) {
                self.line("{s} = try r.readBytes();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "int")) {
                self.line("{s} = try r.readInt();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "long")) {
                self.line("{s} = try r.readLong();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "double")) {
                self.line("{s} = try r.readDouble();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "int128")) {
                self.line("{s} = try r.readInt128();", .{dest});
            } else if (std.mem.eql(u8, expr.name, "int256")) {
                self.line("{s} = try r.readInt256();", .{dest});
            } else {
                unreachable;
            }
            return false;
        } else if (self.cycle_types.contains(expr.name)) {
            // Recursive type: heap-allocate the nested value.
            const ptr = self.fresh("ptr_");
            self.indentTo(extra);
            self.line("const {s} = allocator.create({s}) catch return error.OutOfMemory;", .{ ptr, self.typePath(expr.name) });
            self.indentTo(extra);
            self.line("{s}.* = try {s}.deserialize(allocator, r);", .{ ptr, self.typePath(expr.name) });
            self.indentTo(extra);
            self.line("{s} = {s};", .{ dest, ptr });
            return true;
        } else {
            self.line("{s} = try {s}.deserialize(allocator, r);", .{ dest, self.typePath(expr.name) });
            return true;
        }
    }

    fn emitUnion(self: *Emitter, result_type: []const u8) std.mem.Allocator.Error!void {
        const uname = self.decl_names.get(result_type) orelse naming.lastSegment(self.typePath(result_type));
        var tags: std.ArrayList(*const ast.Constructor) = .empty;
        var seen_tags = std.StringHashMap(void).init(self.allocator);
        for (self.schema.constructors) |*c| {
            if (skipDecl(c)) continue;
            if (!std.mem.eql(u8, c.result_type.name, result_type)) continue;
            const tag = naming.lastSegment(c.name);
            const gop = try seen_tags.getOrPut(tag);
            if (gop.found_existing) continue; // duplicate tag within union: first wins (schema validation flags duplicates)
            try tags.append(self.allocator, c);
        }

        self.line("pub const {s} = union(enum) {{", .{uname});
        for (tags.items) |c| {
            self.line("    {s}: {s},", .{ naming.lastSegment(try self.qualifiedCtorPath(c.name)), try self.qualifiedCtorPath(c.name) });
        }

        // serialize
        self.raw("\n    pub fn serialize(self: *const @This(), w: *Writer) TlError!void {\n        switch (self.*) {\n");
        self.raw("            inline else => |v| {\n");
        self.raw("                try w.writeConstructorId(@TypeOf(v).constructor_id);\n");
        self.raw("                try v.serialize(w);\n");
        self.raw("            },\n        }\n    }\n");

        // deserialize
        self.raw("\n    pub fn deserialize(allocator: std.mem.Allocator, r: *Reader) TlError!@This() {\n");
        self.raw("        const id = try r.readConstructorId();\n        switch (id) {\n");
        for (tags.items) |c| {
            const path = try self.qualifiedCtorPath(c.name);
            const tag = naming.lastSegment(path);
            self.line("            {s}.constructor_id => return .{{ .{s} = try {s}.deserialize(allocator, r) }},", .{ path, tag, path });
        }
        self.raw("            else => return error.InvalidValue,\n        }\n    }\n");
        self.line("}};", .{});
        self.raw("\n");
    }

    /// Constructor struct path with every segment keyword-escaped, usable
    /// from inside any namespace container (top-level names resolve through
    /// file scope automatically). Collisions are resolved with a `_`
    /// suffix: a top-level constructor named like a namespace (`updates`),
    /// and a constructor whose last segment equals its own namespace
    /// (`contacts.contacts` would shadow the `contacts` namespace).
    fn computeCtorPath(self: *Emitter, name: []const u8, ns_set: *std.StringHashMap(void)) std.mem.Allocator.Error![]const u8 {
        var buf: std.ArrayList(u8) = .empty;
        const ns = naming.namespaceOf(name);
        var it = std.mem.splitScalar(u8, name, '.');
        var first = true;
        while (it.next()) |seg| {
            if (!first) try buf.append(self.allocator, '.');
            first = false;
            var piece = try naming.ident(self.allocator, seg);
            const is_last = it.index == null;
            if ((ns.len == 0 and is_last and ns_set.contains(piece)) or
                (ns.len > 0 and is_last and std.mem.eql(u8, piece, ns)))
            {
                piece = try std.fmt.allocPrint(self.allocator, "{s}_", .{piece});
            }
            try buf.appendSlice(self.allocator, piece);
        }
        return buf.items;
    }

    fn qualifiedCtorPath(self: *Emitter, name: []const u8) std.mem.Allocator.Error![]const u8 {
        return self.refPath(self.ctor_paths.get(name) orelse name);
    }

    fn computeTypePath(self: *Emitter, name: []const u8, root_shorts: *std.StringHashMap(void)) std.mem.Allocator.Error![]const u8 {
        const ns = naming.namespaceOf(name);
        const short = naming.lastSegment(name);
        if (ns.len == 0) return short;
        if (root_shorts.contains(short)) {
            return std.fmt.allocPrint(self.allocator, "{s}.{s}_", .{ ns, short });
        }
        return name;
    }

    fn typePath(self: *Emitter, name: []const u8) []const u8 {
        return self.refPath(self.type_paths.get(name) orelse name);
    }

    /// Qualifies `path` for the file currently being emitted. Single-file
    /// mode (cur_ns null) keeps every path fully qualified relative to the
    /// file scope. Split mode routes everything through the entry module
    /// import (`api.`), whose re-exports mirror the single-file surface —
    /// so a reference compiles to the same declaration path regardless of
    /// which file declares it.
    fn refPath(self: *Emitter, path: []const u8) []const u8 {
        if (self.cur_ns == null) return path;
        return std.fmt.allocPrint(self.allocator, "api.{s}", .{path}) catch unreachable;
    }

    /// Emits `registry.zig`: every non-generic wire id with its full TL
    /// name, sorted by id, plus a binary-search lookup helper. Pure data —
    /// no imports.
    fn emitRegistry(self: *Emitter) std.mem.Allocator.Error!void {
        const Entry = struct { id: u32, name: []const u8 };
        var list: std.ArrayList(Entry) = .empty;
        for ([_][]const ast.Constructor{ self.schema.constructors, self.schema.functions }) |decls| {
            for (decls) |*c| {
                if (skipDecl(c)) continue;
                try list.append(self.allocator, .{ .id = c.id, .name = c.name });
            }
        }
        std.mem.sort(Entry, list.items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                if (a.id != b.id) return a.id < b.id;
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lt);

        self.line("//! GENERATED by td TL code generator from \"{s}\".", .{self.opts.source_name});
        self.line("//! Do not edit by hand; regenerate with td-gen.", .{});
        self.raw("\npub const Entry = struct { id: u32, name: []const u8 };\n");
        self.raw("\npub const entries = [_]Entry{\n");
        for (list.items) |e| {
            self.line("    .{{ .id = 0x{x:0>8}, .name = \"{s}\" }},", .{ e.id, e.name });
        }
        self.raw("};\n");
        self.raw(
            \\
            \\/// Name of the constructor or function for a wire id, if known.
            \\pub fn nameFor(id: u32) ?[]const u8 {
            \\    var lo: usize = 0;
            \\    var hi: usize = entries.len;
            \\    while (lo < hi) {
            \\        const mid = lo + (hi - lo) / 2;
            \\        if (entries[mid].id < id) {
            \\            lo = mid + 1;
            \\        } else if (entries[mid].id > id) {
            \\            hi = mid;
            \\        } else {
            \\            return entries[mid].name;
            \\        }
            \\    }
            \\    return null;
            \\}
            \\
        );
    }

    /// Collects named-type dependencies of `expr` (through vector nesting)
    /// that are emitted unions.
    fn appendNamedDeps(self: *Emitter, expr: *const ast.TypeExpr, emitted: *std.StringHashMap(void), out: *std.ArrayList([]const u8)) std.mem.Allocator.Error!void {
        if (naming.isVector(expr)) return self.appendNamedDeps(expr.arg.?, emitted, out);
        if (naming.scalarZigType(expr.name) != null) return;
        if (naming.isTypeVarRef(expr)) return;
        if (emitted.contains(expr.name)) try out.append(self.allocator, expr.name);
    }

    /// True when `target` is reachable from `target` via `edges` (depth-first).
    fn reaches(self: *Emitter, visited: *std.StringHashMap(void), edges: std.StringHashMap(std.ArrayList([]const u8)), from: []const u8, target: []const u8) std.mem.Allocator.Error!bool {
        const list = edges.get(from) orelse return false;
        for (list.items) |dep| {
            if (std.mem.eql(u8, dep, target)) return true;
            const gop = try visited.getOrPut(dep);
            if (gop.found_existing) continue;
            if (try self.reaches(visited, edges, dep, target)) return true;
        }
        return false;
    }

    /// Zig type for a TL type expression, routing named combinator types
    /// through the union rename map. Cyclic result types use `*T` pointers
    /// (Zig cannot lay out recursive by-value structs).
    fn zigTypeMapped(self: *Emitter, expr: *const ast.TypeExpr) []const u8 {
        if (naming.isVector(expr)) {
            const inner = self.zigTypeMapped(self.boxedElemExpr(expr.arg.?, naming.isBareVector(expr)));
            return std.fmt.allocPrint(self.allocator, "[]{s}", .{inner}) catch unreachable;
        }
        if (naming.isTypeVarRef(expr)) return "[]const u8";
        if (naming.scalarZigType(expr.name)) |s| return s;
        if (self.cycle_types.contains(expr.name)) {
            return std.fmt.allocPrint(self.allocator, "*{s}", .{self.typePath(expr.name)}) catch unreachable;
        }
        return self.typePath(expr.name);
    }

    /// Boxed element view for bare `vector<...>` fields: a lowercase
    /// constructor reference (`vector<future_salt>`) still serializes its
    /// elements with constructor ids on the wire (verified against the
    /// hand-parsed `future_salts`), so the element routes through the
    /// result-type union rather than the bare struct. Already-boxed
    /// references (result-type names) pass through unchanged; `force`
    /// applies only to bare vectors.
    fn boxedElemExpr(self: *Emitter, elem: *const ast.TypeExpr, force: bool) *const ast.TypeExpr {
        if (!force) return elem;
        if (self.type_paths.contains(elem.name)) return elem;
        if (self.schema.findByName(elem.name)) |c| {
            const copy = self.allocator.create(ast.TypeExpr) catch unreachable;
            copy.* = elem.*;
            copy.name = c.result_type.name;
            return copy;
        }
        return elem;
    }

    /// Zig type for a function's result — the `Result` decl the RPC layer's
    /// typed `invoke` reads. Unlike field types, a top-level named result is
    /// always by value: its `deserialize` heap-allocates recursive internals
    /// itself. Vector elements follow the generated field rules (recursive
    /// types stay pointer-boxed so `[]*T` decodes elementwise).
    fn resultTypeMapped(self: *Emitter, expr: *const ast.TypeExpr) []const u8 {
        if (naming.isVector(expr)) {
            return std.fmt.allocPrint(self.allocator, "[]{s}", .{self.resultElemType(expr.arg.?)}) catch unreachable;
        }
        if (naming.scalarZigType(expr.name)) |s| return s;
        return self.typePath(expr.name);
    }

    fn resultElemType(self: *Emitter, expr: *const ast.TypeExpr) []const u8 {
        if (naming.isVector(expr)) {
            return std.fmt.allocPrint(self.allocator, "[]{s}", .{self.resultElemType(expr.arg.?)}) catch unreachable;
        }
        if (naming.scalarZigType(expr.name)) |s| return s;
        if (self.cycle_types.contains(expr.name)) {
            return std.fmt.allocPrint(self.allocator, "*{s}", .{self.typePath(expr.name)}) catch unreachable;
        }
        return self.typePath(expr.name);
    }

    /// Whether `expr` resolves to an emitted type: every named type in a
    /// `Result` must have a generated union (all scalar and vector-of-
    /// scalar shapes are fine by construction).
    fn resultEmittable(self: *Emitter, expr: *const ast.TypeExpr) bool {
        if (naming.isVector(expr)) return self.resultEmittable(expr.arg.?);
        if (naming.isTypeVarRef(expr)) return false;
        if (naming.scalarZigType(expr.name) != null) return true;
        return self.type_paths.contains(expr.name);
    }
};
