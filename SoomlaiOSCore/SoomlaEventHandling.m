//
//  SoomlaEventHandling.m
//  SoomlaiOSProfile
//
//  Created by Gur Dotan on 6/2/14.
//  Copyright (c) 2014 Soomla. All rights reserved.
//

#import "SoomlaEventHandling.h"
#import "BadgeReward.h"


@implementation SoomlaEventHandling

+ (void)observeAllEventsWithObserver:(id)observer withSelector:(SEL)selector {
    [[NSNotificationCenter defaultCenter] addObserver:observer selector:selector name:EVENT_REWARD_GIVEN object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:observer selector:selector name:EVENT_REWARD_TAKEN object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:observer selector:selector name:EVENT_CUSTOM object:nil];
}

+ (void)postRewardGiven:(Reward *)reward {
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:reward forKey:DICT_ELEMENT_REWARD];
    [[NSNotificationCenter defaultCenter] postNotificationName:EVENT_REWARD_GIVEN object:self userInfo:userInfo];
}

+ (void)postRewardTaken:(Reward *)reward {
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:reward forKey:DICT_ELEMENT_REWARD];
    [[NSNotificationCenter defaultCenter] postNotificationName:EVENT_REWARD_TAKEN object:self userInfo:userInfo];
}

+ (void)postCustomEventWithName:(NSString*)name andExtraInfo:(NSDictionary*)extra {
    NSDictionary* userInfo = @{
                               DICT_ELEMENT_NAME: name,
                               DICT_ELEMENT_EXTRA: extra
                               };
    [[NSNotificationCenter defaultCenter] postNotificationName:EVENT_CUSTOM object:self userInfo:userInfo];
}

@end
