// tdzig codegen golden schema: exercises every generated-code feature —
// unions, flags/optionals (incl. ?true), keyword parameter names
// (`type`, `long`), bytes, doubles, nested vectors, namespaced
// constructors and functions.
boolFalse#bc799737 = Bool;
boolTrue#997275b5 = Bool;
photoSize#e17e23c type:string w:int h:int size:int = PhotoSize;
geoPoint#2042cdd9 long:double lat:double = GeoPoint;
userProfilePhoto#82d1f706 flags:# has_video:flags.0?true photo_id:long stripped_thumb:flags.1?bytes dc_id:int = UserProfilePhoto;
user#d10d979a flags:# self:flags.10?true id:long first_name:flags.1?string last_name:flags.2?string photo:flags.5?UserProfilePhoto tags:Vector<Vector<int>> = User;
---functions---
users.getUsers#d91a548 id:Vector<int> = Vector<User>;
