//
//  TimeStrategy.m
//  SoomlaiOSCore
//
//  Created by Refael Dakar on 06/08/14.
//  Copyright (c) 2014 SOOMLA. All rights reserved.
//

#import "TimeStrategy.h"
#import "JSONConsts.h"
#import "SoomlaUtils.h"

@implementation TimeStrategy

@synthesize strategy, startTime, repeatTimes;

static NSString* TAG = @"SOOMLA TimeStrategy";

- (id) initWithStrategy:(Strategy)oStrategy andStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes {
    if (self = [super init]) {
        strategy = oStrategy;
        startTime = oStartTime;
        repeatTimes = oRepeatTimes;
    }
    return self;
}

+ (TimeStrategy*)Once {
    return [self OnceWithStartTime:NULL];
}

+ (TimeStrategy*)OnceWithStartTime:(NSDate*)oStartTime {
    return [self CustomWithStartTime:oStartTime andRepeatTimes:1];
}

+ (TimeStrategy*)EveryMonthWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes {
    return [[TimeStrategy alloc] initWithStrategy:EVERYMONTH andStartTime:oStartTime andRepeatTimes:oRepeatTimes];
}

+ (TimeStrategy*)EveryDayWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes {
    return [[TimeStrategy alloc] initWithStrategy:EVERYDAY andStartTime:oStartTime andRepeatTimes:oRepeatTimes];
}

+ (TimeStrategy*)EveryHourWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes {
    return [[TimeStrategy alloc] initWithStrategy:EVERYHOUR andStartTime:oStartTime andRepeatTimes:oRepeatTimes];
}

+ (TimeStrategy*)CustomWithRepeatTimes:(int)oRepeatTimes {
    return [self CustomWithStartTime:NULL andRepeatTimes:oRepeatTimes];
}

+ (TimeStrategy*)CustomWithStartTime:(NSDate*)oStartTime andRepeatTimes:(int)oRepeatTimes {
    return [[TimeStrategy alloc] initWithStrategy:CUSTOM andStartTime:oStartTime andRepeatTimes:oRepeatTimes];
}

+ (TimeStrategy*)Always {
    return [self AlwaysWithStartTime:NULL];
}

+ (TimeStrategy*)AlwaysWithStartTime:(NSDate*)oStartTime {
    return [[TimeStrategy alloc] initWithStrategy:ALWAYS andStartTime:oStartTime andRepeatTimes:0];
}

- (id)initWithDictionary:(NSDictionary *)dict {
    if (self = [super init]) {
        strategy = [dict[SOOM_TS_KIND] intValue];
        repeatTimes = [dict[SOOM_TS_KIND] intValue];
        
        NSString* startTimeStr = [dict[SOOM_TS_START] stringValue];
        if (startTimeStr && [startTimeStr length] > 0) {
            long long startTimeMillis = [startTimeStr longLongValue];
            startTime = [NSDate dateWithTimeIntervalSince1970:(startTimeMillis/1000)];
        }
    }
    
    return self;

}

- (NSDictionary *)toDictionary {
    return @{
             SOOM_TS_KIND: [NSNumber numberWithInt:strategy],
             SOOM_TS_START: (startTime ?
                             [NSString stringWithFormat:@"%lld",(long long)([startTime timeIntervalSince1970] * 1000)] :
                             @""),
             SOOM_TS_REPEAT: [NSNumber numberWithInt:repeatTimes]
             };
}

- (BOOL)approveWithLastTime:(NSDate*)lastTime andTimesApproved:(int)timesApproved {
    NSDate* now = [NSDate date];
    
    if ([now compare:self.startTime] == NSOrderedAscending) {
        LogDebug(TAG, @"Time to start approval hasn't come yet.");
        return NO;
    }
    
    if (self.strategy == ALWAYS) {
        LogDebug(TAG, @"The strategy is ALWAYS.");
        return YES;
    }
    
    if (self.repeatTimes>0 && timesApproved >= self.repeatTimes) {
        LogDebug(TAG, @"Approval limit exceeded.");
        return NO;
    }
    
    if (self.strategy == CUSTOM) {
        LogDebug(TAG, @"The strategy is CUSTOM and approval limit not reached.");
        return YES;
    }
    
    if (self.startTime == NULL) {
        LogError(TAG, @"The strategy is related to times but StartTime is null.");
        return NO;
    }
    
    if (lastTime == NULL) {
        LogDebug(TAG, @"The strategy is related to times and we didn't get a valid lastTime. This means that it's the first time.");
        return YES;
    }
    
    if (self.strategy == EVERYHOUR) {
        LogDebug(TAG, @"The strategy is EVERYHOUR.");
        NSTimeInterval secs = [now timeIntervalSinceDate:lastTime];
        int hours = secs / 3600;
        return hours >= 1;
    }
    
    if (self.strategy == EVERYDAY) {
        LogDebug(TAG, @"The strategy is EVERYDAY.");
        NSInteger days = [[[NSCalendar currentCalendar] components: NSCalendarUnitDay
                                                            fromDate: lastTime
                                                              toDate: now
                                                             options: 0] day];
        return days >= 1;
    }
    
    if (self.strategy == EVERYMONTH) {
        LogDebug(TAG, @"The strategy is EVERYMONTH.");
        
        NSInteger months = [[[NSCalendar currentCalendar] components: NSCalendarUnitMonth
                                                           fromDate: lastTime
                                                             toDate: now
                                                            options: 0] month];
        
        return months >= 1;
    }
    
    return false;
}


@end
