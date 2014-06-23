/*
 Copyright (C) 2012-2014 Soomla Inc.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#import "Reward.h"
#import "JSONConsts.h"
#import "RewardStorage.h"
#import "SoomlaUtils.h"
#import "DictionaryFactory.h"
#import "SoomlaEventHandling.h"

@implementation Reward

@synthesize rewardId, name, repeatable;

static NSString* TAG = @"SOOMLA Reward";
static NSString* TYPE_NAME = @"reward";
static DictionaryFactory* dictionaryFactory;


- (id)initWithRewardId:(NSString *)oRewardId andName:(NSString *)oName {
    self = [super init];
    if ([self class] == [Reward class]) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Error, attempting to instantiate AbstractClass directly." userInfo:nil];
    }
    
    if (self) {
        self.rewardId = oRewardId;
        self.name = oName;
    }
    return self;
}

- (id)initWithDictionary:(NSDictionary *)dict {
    self = [super init];
    if ([self class] == [Reward class]) {
        @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                       reason:@"Error, attempting to instantiate AbstractClass directly." userInfo:nil];
    }
    
    if (self) {
        self.rewardId = dict[SOOM_REWARD_REWARDID];
        self.name = dict[SOOM_NAME];
        self.repeatable = [dict[SOOM_REWARD_REPEAT] boolValue];
    }
    
    return self;
}

- (NSDictionary *)toDictionary {
    return [[NSDictionary alloc] initWithObjectsAndKeys:
            self.rewardId, SOOM_REWARD_REWARDID,
            self.name, SOOM_NAME,
            self.repeatable, SOOM_REWARD_REPEAT,
            nil];
}

- (BOOL)give {
    if ([RewardStorage isRewardGiven:self] && !self.repeatable) {
        LogDebug(TAG, ([NSString stringWithFormat:@"Reward was already given and is not repeatable. id: %@", self.rewardId]));
        return NO;
    }

    if ([self giveInner]) {
        [RewardStorage setStatus:YES forReward:self];
        return YES;
    }
    
    return NO;
}

- (BOOL)take {
    if ([RewardStorage isRewardGiven:self]) {
        LogDebug(TAG, ([NSString stringWithFormat:@"Reward not give. id: %@", self.rewardId]));
        return NO;
    }
    
    if ([self takeInner]) {
        [RewardStorage setStatus:NO forReward:self];
        [SoomlaEventHandling postRewardTaken:self];
        return YES;
    }
    return NO;
}

- (BOOL)isOwned {
    return [RewardStorage isRewardGiven:self];
}

- (BOOL)giveInner {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override %@ in a subclass",
                                           NSStringFromSelector(_cmd)]
                                 userInfo:nil];
}

- (BOOL)takeInner {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException
                                   reason:[NSString stringWithFormat:@"You must override %@ in a subclass",
                                           NSStringFromSelector(_cmd)]
                                 userInfo:nil];
}


// Static methods

+ (Reward *)fromDictionary:(NSDictionary *)dict {
    return (Reward *)[dictionaryFactory createObjectWithDictionary:dict];
}

+ (void)initialize {
    if (self == [Reward self]) {
        dictionaryFactory = [[DictionaryFactory alloc] init];
    }
}


@end
